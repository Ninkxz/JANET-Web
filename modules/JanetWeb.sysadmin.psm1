# =============================================================================
#  JanetWeb.sysadmin.psm1  ->  Sysadmin Sweeps (read-only fleet WinRM sweeps)
#
#  Net-new JANET Web tool (no desktop twin). READ-ONLY: three parallel per-host
#  WinRM sweeps that surface the common AFNET findings you are already on the box
#  for. Each sweep is a runspace-pool fan-out that mirrors the WPT bulk-scan
#  pattern (TCP reachability probe -> New-PSSession -> ONE read-only Invoke-Command
#  round-trip -> emit rows). It CHANGES NOTHING on any host: every remote read is
#  Get-CimInstance / a registry Test-Path / a Cert:\ read / a local-group ADSI
#  enumeration. No action is destructive.
#
#  Software-inventory / EOL was DELIBERATELY NOT built as a fourth sweep: the WPT
#  Software Manager (CCM_Application picker + uninstall) and the UPR tool already
#  own that surface, so a sysadmin inventory sweep would duplicate them.
#
#  Sweeps (all destructive=$false):
#    localadmin-sweep    - members of the local Administrators group per host.
#                          Row: Host, Online, Admins (; joined), AdminCount, Error
#    certexpiry-sweep    - Cert:\LocalMachine\My certs expiring within N days
#                          (default 90). ONE row per expiring cert (already-expired
#                          included as negative DaysLeft). Row: Host, Online,
#                          Subject, Issuer, Expires (yyyy-MM-dd), DaysLeft (int),
#                          Thumbprint, Error. A host with none emits one note row.
#    rebootpending-sweep - reboot-pending status from the three standard signals.
#                          Row: Host, Online, RebootPending (bool), Reasons, Error
#
#  v1.0.2 (audit 2026-07-25 (fable re-audit follow-up)) - the amber matcher ran over
#    the WHOLE report line, hostname included, so a CLEAN host whose NAME carries a
#    state word ('WS-ERROR-01', 'TIMEOUT-LAB-02') was logged amber. The state markers
#    are now matched against the state portion of the line only, via the pure
#    Get-SysadminReportLevel helper (unit-tested, no WinRM).
#
#  v1.0.1 (audit 2026-07-24) - correctness pass on output that was silently wrong:
#    * the remote-probe wrapper array-wrapped the payload a SECOND time, so every
#      sweep unwrapped a 1-element array-OF-array: Local Admins always reported
#      AdminCount=1, reboot-pending was a 100% false positive, and cert expiry
#      reported a false CLEAN on any host with >1 cert. Wrapper extracted to
#      New-SysadminProbeBlock and pinned by tests\Sysadmin.Tests.ps1.
#    * 'days = 0' (already-expired only) is now honoured instead of being rewritten,
#      and junk input keeps the default instead of collapsing to 0.
#    * CLEAN hosts are no longer logged amber by a substring match on the prose.
#
#  Pure, unit-testable logic lives in named helper functions (Get-SysadminDaysLeft,
#  Join-SysadminReasons, Get-SysadminCleanMembers, Format-SysadminAdminList,
#  Get-SysadminIntParam, New-SysadminProbeBlock) so the Pester suite exercises them
#  WITHOUT any WinRM. The per-host worker is a single
#  module-scope scriptblock ($script:SysadminSweepBlock) whose reachability probe,
#  session, and remote round-trip go through named/built-in commands so the tests
#  can shim Test-SysadminReachable / New-PSSession / Invoke-Command and drive the
#  row-building against synthetic data (mirrors tests\Wpt.Guards.Tests.ps1).
#
#  Contract (server convention):
#    Get-JanetToolManifest                                       -> descriptors
#    Invoke-JanetToolAction -ActionId -Params -Credential -Emit  -> { rows; summary }
#  PowerShell 5.1 only. ASCII-only body; UTF-8 WITH BOM.
# =============================================================================

# Own module path, captured at load, so a pool runspace can Import-Module it to get
# the helper functions (the worker calls them). Guarded by Get-Command in the worker
# so running the worker IN module scope (the Pester shim path) never re-imports.
$script:SysadminModulePath = $PSCommandPath

function Get-JanetToolManifest {
    @{
        id       = 'sysadmin'
        name     = 'Sysadmin Sweeps'
        version  = '1.0.2'   # audit 2026-07-25 (fable re-audit follow-up): amber matcher anchored to the state, not the hostname
        category = 'Reporting'
        summary  = 'Read-only WinRM fleet sweeps for common AFNET findings you are already on the box for. Three parallel per-host sweeps: Local Administrators membership, certificate expiry (Cert:\LocalMachine\My within N days, already-expired included), and reboot-pending status (CBS + Windows Update + PendingFileRenameOperations). Fans one worker per host (TCP reachability probe -> session -> one read-only Invoke-Command), streams a per-host summary to the activity log, and changes nothing. Software inventory/EOL is intentionally not here - the WPT Software Manager + UPR own it.'
        actions  = @(
            @{
                id          = 'localadmin-sweep'
                label       = 'Local Admins Sweep'
                description = 'Read-only: enumerate the members of the local Administrators group (resolved by well-known SID S-1-5-32-544, so it is locale-independent) on each host and emit one row per host: Host, Online, Admins (semicolon-joined member names), AdminCount, Error. Changes nothing.'
                kind        = 'stream-table'
                destructive = $false
                columns     = @('Host','Online','Admins','AdminCount','Error')
                inputs      = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts (1-32)'; type='int'; required=$false; default=16 }
                )
            }
            @{
                id          = 'certexpiry-sweep'
                label       = 'Cert Expiry Sweep'
                description = 'Read-only: read Cert:\LocalMachine\My on each host and report certificates expiring within N days (default 90). One row PER expiring cert - already-expired certs are included with a negative DaysLeft (computed on the server from NotAfter). A host with nothing expiring emits a single note row. Columns: Host, Online, Subject, Issuer, Expires (yyyy-MM-dd), DaysLeft, Thumbprint, Error. Changes nothing.'
                kind        = 'stream-table'
                destructive = $false
                columns     = @('Host','Online','Subject','Issuer','Expires','DaysLeft','Thumbprint','Error')
                inputs      = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='days'; label='Expiring within (days)'; type='int'; required=$false; default=90 },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts (1-32)'; type='int'; required=$false; default=16 }
                )
            }
            @{
                id          = 'rebootpending-sweep'
                label       = 'Reboot Pending Sweep'
                description = 'Read-only: report reboot-pending status per host from the three standard signals - Component Based Servicing (CBS\RebootPending), Windows Update (WindowsUpdate\Auto Update\RebootRequired), and PendingFileRenameOperations (Session Manager). One row per host: Host, Online, RebootPending (bool), Reasons (which signals fired), Error. Changes nothing.'
                kind        = 'stream-table'
                destructive = $false
                columns     = @('Host','Online','RebootPending','Reasons','Error')
                inputs      = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts (1-32)'; type='int'; required=$false; default=16 }
                )
            }
        )
    }
}

# --- Pure, unit-testable helpers -------------------------------------------

# Whole days from $Now until $NotAfter (floor). Negative when already expired.
function Get-SysadminDaysLeft {
    param([datetime]$NotAfter, [datetime]$Now = (Get-Date))
    return [int][math]::Floor((New-TimeSpan -Start $Now -End $NotAfter).TotalDays)
}

# Clean (trim, drop null/blank) + case-insensitive de-dup a member list.
# Returns a plain [string[]] via ToArray() (never ,@()).
function Get-SysadminCleanMembers {
    param([string[]]$Members)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $ordered = New-Object System.Collections.ArrayList
    foreach ($m in @($Members)) {
        $s = ([string]$m).Trim()
        if ($s -and $seen.Add($s)) { [void]$ordered.Add($s) }
    }
    return $ordered.ToArray()
}

# Semicolon-join the cleaned local Administrators members into a display string.
function Format-SysadminAdminList {
    param([string[]]$Members)
    return ((Get-SysadminCleanMembers -Members $Members) -join '; ')
}

# Parse an operator-supplied int, keeping $Default ONLY when the value is absent
# or unparseable. audit 2026-07-24: the call sites below used  if ($Params['x'])
# plus a DISCARDED [int]::TryParse, which is wrong twice - a legitimate 0 is falsy
# so 'certs expiring within 0 days' (already-expired only) was silently rewritten
# to 90, and on junk input TryParse ZEROES its out param, so the discarded result
# meant junk became 0 rather than the default. Explicit + pure so Pester pins it.
function Get-SysadminIntParam {
    param($Value, [int]$Default)
    if ($null -eq $Value) { return $Default }
    $s = ([string]$Value).Trim()
    if ($s -eq '') { return $Default }
    $parsed = 0
    if ([int]::TryParse($s, [ref]$parsed)) { return $parsed }
    return $Default
}

# Clean + join reboot-pending signal names into one display string ('' when none).
function Join-SysadminReasons {
    param([string[]]$Reasons)
    $clean = New-Object System.Collections.ArrayList
    foreach ($x in @($Reasons)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$x)) { [void]$clean.Add(([string]$x).Trim()) }
    }
    return ($clean -join '; ')
}

# Activity-log level for one per-host report line ('info' or 'warn').
#
# Every report this module builds is shaped "<host> : <state>...", so the state
# markers are matched against the STATE PORTION ONLY - everything after the first
# ' : ' - never the whole line (audit 2026-07-25 (fable re-audit follow-up)): the
# hostname sits in front of it, so a perfectly CLEAN box literally named
# 'WS-ERROR-01' or 'TIMEOUT-LAB-02' was rendered amber purely because of its name,
# and an operator triaging by colour would chase a host with nothing wrong with it.
# The markers are further anchored to the START of the state ('SESSION ERROR - ...',
# 'OFFLINE - ...', 'REBOOT PENDING - ...'), which also stops a local-admin row from
# ambering on a MEMBER name that happens to contain one ('CORP\ERROR-SVC').
#
# -cmatch (case-SENSITIVE) on the uppercase markers is kept from audit 2026-07-24:
# it is what keeps the clean prose forms ('no reboot pending', 'no certs expiring
# within N day(s)') out of the amber bucket. A line that does not parse falls back
# to the whole string, so a real finding is never silently downgraded to info.
function Get-SysadminReportLevel {
    param([string]$Report)
    $rpt = [string]$Report
    if ([string]::IsNullOrWhiteSpace($rpt)) { return 'info' }
    # Hostnames are validated bare tokens (no spaces, no colons) before any sweep,
    # so the first ' : ' is unambiguously the host/state separator.
    $state = $rpt
    $m = [regex]::Match($rpt, '^\s*[^\s:]+\s*:\s*(?<s>.*)$')
    if ($m.Success) { $state = $m.Groups['s'].Value }
    if ($state -cmatch '^[A-Z ]*(?:ERROR|OFFLINE|TIMEOUT|CANCELLED|DNS MISMATCH|REBOOT PENDING)') { return 'warn' }
    if ($state -match '\d+ cert\(s\) expiring') { return 'warn' }
    return 'info'
}

# --- Reachability (AFNET-safe: TCP only, NEVER ICMP) ------------------------
# A named function (not inlined) so the Pester suite can shim it and drive the
# worker's post-reachability path without a real socket. Probes WinRM HTTP 5985,
# then WinRM HTTPS 5986, then SMB 445 (liveness only), breaking on first connect
# (5985 preferred when both are open). $UseSsl (a [ref] out param) is set $true
# only when the host answered ONLY on 5986, so the caller's session can switch to
# -UseSSL (mirrors the C2C pattern).
function Test-SysadminReachable {
    param([string]$ComputerName, [int[]]$Ports = @(5985, 5986, 445), [int]$TimeoutMs = 1500, [ref]$UseSsl)
    if ($UseSsl) { $UseSsl.Value = $false }
    if ([string]::IsNullOrWhiteSpace($ComputerName)) { return $false }
    foreach ($port in $Ports) {
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($ComputerName, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false) -and $tc.Connected) {
                if ($port -eq 5986 -and $UseSsl) { $UseSsl.Value = $true }
                return $true
            }
        } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
    }
    return $false
}

# --- Remote read-only probes (one per sweep) --------------------------------
# Each runs in ONE Invoke-Command round-trip on the target and returns raw data;
# the worker (server-side) computes verdicts / DaysLeft and builds display rows.
function Get-SysadminRemoteBlock {
    param([string]$SweepId)
    switch ($SweepId) {
        'localadmin-sweep' {
            return {
                # Resolve the local Administrators group by its well-known SID so the
                # name is locale-independent, then enumerate members via the WinNT
                # ADSI provider (local call - no double-hop). Read-only.
                $sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
                $localName = (($sid.Translate([System.Security.Principal.NTAccount]).Value) -split '\\')[-1]
                $group = [ADSI]("WinNT://./$localName,group")
                $names = New-Object System.Collections.ArrayList
                foreach ($m in @($group.psbase.Invoke('Members'))) {
                    try {
                        $path = ([ADSI]$m).psbase.Path
                        $p = ($path -replace '^WinNT://', '')
                        $parts = @($p -split '/')
                        if ($parts.Count -ge 2) { [void]$names.Add(('{0}\{1}' -f $parts[-2], $parts[-1])) }
                        elseif ($parts.Count -ge 1) { [void]$names.Add([string]$parts[-1]) }
                    } catch {}
                }
                return ,@($names.ToArray())
            }
        }
        'certexpiry-sweep' {
            return {
                # Read the machine personal store; return raw fields (NotAfter as-is).
                # DaysLeft + the within-N-days filter are computed on the server.
                $out = New-Object System.Collections.ArrayList
                foreach ($c in @(Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction Stop)) {
                    [void]$out.Add([pscustomobject]@{
                        Subject    = [string]$c.Subject
                        Issuer     = [string]$c.Issuer
                        NotAfter   = $c.NotAfter
                        Thumbprint = [string]$c.Thumbprint
                    })
                }
                return ,@($out.ToArray())
            }
        }
        'rebootpending-sweep' {
            return {
                # The three standard reboot-pending signals. Read-only Test-Path /
                # registry read; returns the list of signals that fired.
                $reasons = New-Object System.Collections.ArrayList
                if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction SilentlyContinue) {
                    [void]$reasons.Add('Component Based Servicing')
                }
                if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction SilentlyContinue) {
                    [void]$reasons.Add('Windows Update')
                }
                try {
                    $sm = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
                    if ($sm -and $sm.PendingFileRenameOperations) {
                        $vals = @($sm.PendingFileRenameOperations | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
                        if ($vals.Count -gt 0) { [void]$reasons.Add('PendingFileRenameOperations') }
                    }
                } catch {}
                return ,@($reasons.ToArray())
            }
        }
        default { return $null }
    }
}

# Wrap a probe payload so ONE Invoke-Command round-trip returns both the remote
# computer name (for the DNS-mismatch guard below) and the payload's data. The
# wrapper is rebuilt from the payload's TEXT because a scriptblock cannot ride
# along as a remoting argument.
#
# audit 2026-07-24: this used to be  '__SweepData = @(& { <payload> })'  - a
# DOUBLE array wrap. Every payload already returns its array as a SINGLE object
# via the  return ,@(...)  idiom, so the extra @() re-wrapped it and each sweep
# unwrapped a 1-element array-OF-array: localadmin coerced that one element to a
# single string (AdminCount always 1), rebootpending saw Count=1 on an EMPTY
# reason list (reboot pending always $true), and certexpiry's [datetime] cast
# threw on the nested array whenever a host had >1 cert (silently reporting a
# false CLEAN). A plain sub-expression passes the payload's array through intact.
# Named + exported so tests\Sysadmin.Tests.ps1 can pin the wrap shape with no WinRM.
function New-SysadminProbeBlock {
    param([scriptblock]$Probe)
    if (-not $Probe) { return $null }
    return [scriptblock]::Create('@{ __SweepName = $env:COMPUTERNAME; __SweepData = (& { ' + $Probe.ToString() + ' }) }')
}

# --- Per-host worker (runs in a pool runspace; also runnable in module scope) -
# Returns @{ Host; Online; Error; Rows; Report }. Rows is ALWAYS >= 1 hashtable,
# each carrying the sweep's display columns (the main loop adds a unique _rk and
# emits them). Reachability, session, and the remote round-trip go through
# Test-SysadminReachable / New-PSSession / Invoke-Command so the tests can shim
# them and assert the emitted row shape with NO real WinRM.
$script:SysadminSweepBlock = {
    param(
        [string]$Computer, $Cred, [string]$Auth, [bool]$AttemptOffline,
        [string]$SweepId, [int]$Days, [string]$ModulePath
    )

    # In a bare pool runspace the module functions are absent - import self once so
    # the helpers/probes resolve. In module scope (tests) they already exist, so skip.
    if (-not (Get-Command Get-SysadminDaysLeft -ErrorAction SilentlyContinue)) {
        if ($ModulePath) { try { Import-Module $ModulePath -Force -ErrorAction Stop } catch {} }
    }

    $r = @{ Host = $Computer; Online = $false; Error = ''; Rows = @(); Report = '' }

    # Build a fully-populated base row for this sweep (empty columns), so offline /
    # error rows keep the grid's shape.
    $baseRow = {
        param([bool]$online, [string]$err)
        switch ($SweepId) {
            'localadmin-sweep'    { return @{ Host = $Computer; Online = $online; Admins = ''; AdminCount = 0; Error = $err } }
            'certexpiry-sweep'    { return @{ Host = $Computer; Online = $online; Subject = ''; Issuer = ''; Expires = ''; DaysLeft = ''; Thumbprint = ''; Error = $err } }
            'rebootpending-sweep' { return @{ Host = $Computer; Online = $online; RebootPending = $false; Reasons = ''; Error = $err } }
            default               { return @{ Host = $Computer; Online = $online; Error = $err } }
        }
    }

    # Reachability (TCP 5985/5986/445; $useSsl set when ONLY 5986 answered, so the
    # session below auto-switches to -UseSSL). Offline + not forcing -> one offline row.
    $useSsl = $false
    $reachable = Test-SysadminReachable -ComputerName $Computer -UseSsl ([ref]$useSsl)
    if (-not $reachable -and -not $AttemptOffline) {
        $r.Error = 'Offline (no TCP on 5985/5986/445)'
        $r.Rows = @((& $baseRow $false 'Offline (no TCP on 5985/5986/445)'))
        $r.Report = "$Computer : OFFLINE - no TCP on 5985/5986/445"
        return $r
    }
    $r.Online = [bool]$reachable

    $remote = Get-SysadminRemoteBlock -SweepId $SweepId
    if (-not $remote) {
        $r.Error = "Unknown sweep '$SweepId'"
        $r.Rows = @((& $baseRow $r.Online "Unknown sweep '$SweepId'"))
        return $r
    }

    # -UseSSL only when the host answered ONLY on 5986 (self-signed WinRM HTTPS is
    # common on AFNET, so skip CA/CN validation; port 5986 is implicit).
    $soP = @{ OperationTimeout = 120000; OpenTimeout = 15000; CancelTimeout = 5000; IdleTimeout = 60000 }
    if ($useSsl) { $soP['SkipCACheck'] = $true; $soP['SkipCNCheck'] = $true }
    $wsOpt = New-PSSessionOption @soP
    $splat = @{ ComputerName = $Computer; SessionOption = $wsOpt; ErrorAction = 'Stop' }
    if ($useSsl) { $splat['UseSSL'] = $true }
    if ($Cred) { $splat['Credential'] = $Cred; $splat['Authentication'] = $Auth }
    $sess = $null
    try { $sess = New-PSSession @splat }
    catch {
        $r.Error = "Session: $($_.Exception.Message)"
        $r.Rows = @((& $baseRow $r.Online $r.Error))
        $r.Report = "$Computer : SESSION ERROR - $($_.Exception.Message)"
        return $r
    }

    # audit 2026-07-23: fold the remote computer name into the SAME round-trip
    # (the biosfirmware one-Invoke-Command idiom) so the DNS-mismatch guard below
    # costs no extra remote call. audit 2026-07-24: the wrapper now lives in
    # New-SysadminProbeBlock (it was double-wrapping the payload here).
    $wrapped = New-SysadminProbeBlock -Probe $remote

    $raw = $null
    # audit 2026-07-24: no Remove-PSSession in this catch - the finally below runs
    # on the `return` too, so the old one just closed an already-closed session.
    try { $raw = Invoke-Command -Session $sess -ScriptBlock $wrapped -ErrorAction Stop }
    catch {
        $r.Error = "Probe: $($_.Exception.Message)"
        $r.Rows = @((& $baseRow $r.Online $r.Error))
        $r.Report = "$Computer : PROBE ERROR - $($_.Exception.Message)"
        return $r
    } finally { if ($sess) { try { Remove-PSSession $sess -ErrorAction SilentlyContinue } catch {} } }

    # Unwrap. A shimmed/legacy Invoke-Command may hand back the bare sweep data
    # (no wrapper); then the name is unknown and the guard is skipped (soft-warn
    # guard only - never turns a good probe into an error on its own).
    $remoteName = ''
    if ($raw -is [System.Collections.IDictionary] -and $raw.Contains('__SweepName')) {
        $remoteName = ([string]$raw['__SweepName']).Trim()
        $raw = $raw['__SweepData']
    }

    # DNS-mismatch guard (read-only soft-warn, copied from biosfirmware; audit
    # 2026-07-23): a wrong box (stale DNS / reused IP) would report ITS facts
    # under the dialed name. Session name compare, never PTR. IP-literal targets
    # skip (no DNS indirection - the box answering at that IP IS the box). On
    # mismatch, emit a clearly-marked DNS MISMATCH row instead of wrong-box data.
    $ipLit = $null
    if ($remoteName -and -not [System.Net.IPAddress]::TryParse($Computer, [ref]$ipLit)) {
        $targetShort = ($Computer -split '\.')[0]
        if ($remoteName.ToUpper() -ne $targetShort.ToUpper()) {
            $r.Error = "DNS MISMATCH: dialed '$targetShort' but remote is '$remoteName' - wrong-box data suppressed"
            $r.Rows = @((& $baseRow $r.Online $r.Error))
            $r.Report = "$Computer : DNS MISMATCH - dialed '$targetShort', answered '$remoteName' - skipped"
            return $r
        }
    }

    # ---- Build display rows from the raw remote data (server-side) ----
    $rows = New-Object System.Collections.ArrayList
    switch ($SweepId) {

        'localadmin-sweep' {
            $members = @($raw)
            $clean = @(Get-SysadminCleanMembers -Members $members)
            $row = & $baseRow $r.Online ''
            $row.Admins = (Format-SysadminAdminList -Members $members)
            $row.AdminCount = [int]$clean.Count
            [void]$rows.Add($row)
            $r.Report = "$Computer : $($clean.Count) local admin(s) - $($row.Admins)"
        }

        'certexpiry-sweep' {
            $certs = @($raw)
            $expiring = New-Object System.Collections.ArrayList
            foreach ($c in $certs) {
                if (-not $c) { continue }
                $na = $null
                try { $na = [datetime]$c.NotAfter } catch { continue }
                $dl = Get-SysadminDaysLeft -NotAfter $na
                if ($dl -le $Days) {
                    [void]$expiring.Add([pscustomobject]@{
                        Subject    = [string]$c.Subject
                        Issuer     = [string]$c.Issuer
                        Expires    = $na.ToString('yyyy-MM-dd')
                        DaysLeft   = [int]$dl
                        Thumbprint = [string]$c.Thumbprint
                    })
                }
            }
            $sorted = @($expiring | Sort-Object -Property @{ Expression = { [int]$_.DaysLeft } })
            if ($sorted.Count -eq 0) {
                $row = & $baseRow $r.Online ''
                $row.Subject = "(no certs expiring within $Days day(s))"
                [void]$rows.Add($row)
                $r.Report = "$Computer : no certs expiring within $Days day(s)"
            } else {
                foreach ($e in $sorted) {
                    $row = & $baseRow $r.Online ''
                    $row.Subject = [string]$e.Subject
                    $row.Issuer = [string]$e.Issuer
                    $row.Expires = [string]$e.Expires
                    $row.DaysLeft = [int]$e.DaysLeft
                    $row.Thumbprint = [string]$e.Thumbprint
                    [void]$rows.Add($row)
                }
                $r.Report = "$Computer : $($sorted.Count) cert(s) expiring within $Days day(s)"
            }
        }

        'rebootpending-sweep' {
            # audit 2026-07-24: derive PENDING from the CLEANED signal names, not
            # the raw element count. A probe that returns nothing (or one blank
            # element) is NOT a pending reboot - the raw count is exactly what
            # turned the wrapper double-wrap into a 100% false positive, so keep
            # the verdict tied to a signal we can actually name in Reasons.
            $reasons = @($raw)
            $row = & $baseRow $r.Online ''
            $row.Reasons = (Join-SysadminReasons -Reasons $reasons)
            $pending = -not [string]::IsNullOrWhiteSpace([string]$row.Reasons)
            $row.RebootPending = [bool]$pending
            [void]$rows.Add($row)
            $r.Report = if ($pending) { "$Computer : REBOOT PENDING - $($row.Reasons)" } else { "$Computer : no reboot pending" }
        }
    }

    $r.Rows = @($rows.ToArray())
    return $r
}

function Invoke-JanetToolAction {
    param(
        [string]$ActionId,
        [hashtable]$Params,
        [System.Management.Automation.PSCredential]$Credential,
        [scriptblock]$Emit
    )
    $send = { param($e) if ($Emit) { & $Emit $e } }

    $validActions = @('localadmin-sweep', 'certexpiry-sweep', 'rebootpending-sweep')
    if ($validActions -notcontains $ActionId) {
        & $send @{ type = 'error'; text = "Unknown action '$ActionId'." }
        return @{ rows = @(); summary = @{} }
    }

    # Operator-cancel bridge (server injects $Params['__job']).
    $cancelJob = $null
    if ($Params -and $Params.ContainsKey('__job')) { $cancelJob = $Params['__job'] }
    $cancelCheck = { if ($cancelJob) { try { [bool]$cancelJob['Cancel'] } catch { $false } } else { $false } }.GetNewClosure()

    # Targets: accept only bare host / IPv4 tokens; drop UNC/URL/junk before any WinRM.
    $targets = @(([string]$Params['targets']) -split '[\r\n,;\t ]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and ($_ -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$') } | Select-Object -Unique)
    if ($targets.Count -eq 0) {
        & $send @{ type = 'log'; level = 'warn'; text = 'No valid targets.' }
        return @{ rows = @(); summary = @{ total = 0 } }
    }

    $attemptOffline = $false
    if ($null -ne $Params['attemptOffline']) {
        $av = $Params['attemptOffline']
        $attemptOffline = if ($av -is [bool]) { [bool]$av } else { ("$av" -match '^(?i:true|1|yes|on)$') }
    }
    # audit 2026-07-24: both of these went through Get-SysadminIntParam now - the
    # old  if ($Params['x']) + discarded TryParse  form dropped a legitimate 0
    # (days=0 = 'already-expired only' silently became 90) and turned junk into 0
    # rather than the default. days is still floored at 0 (no negative window).
    $threads = Get-SysadminIntParam -Value $Params['threads'] -Default 16
    $threads = [Math]::Max(1, [Math]::Min(32, $threads))
    $days = 90
    if ($ActionId -eq 'certexpiry-sweep') { $days = Get-SysadminIntParam -Value $Params['days'] -Default 90 }
    if ($days -lt 0) { $days = 0 }

    $perHostTimeout = 150  # a read-only sweep that runs this long = a wedged remote read
    $auth = if ($Credential) { 'Negotiate' } else { 'Default' }
    $authLabel = if ($Credential) { "as $($Credential.UserName)" } else { 'current session' }

    $sweepLabel = switch ($ActionId) {
        'localadmin-sweep'    { 'Local Admins sweep' }
        'certexpiry-sweep'    { "Cert Expiry sweep (<= $days day(s))" }
        'rebootpending-sweep' { 'Reboot Pending sweep' }
        default               { $ActionId }
    }

    & $send @{ type = 'status'; text = "$sweepLabel on $($targets.Count) host(s) with $threads thread(s)..." }
    & $send @{ type = 'log'; level = 'info'; text = "[$(Get-Date -Format 'HH:mm:ss')] START $sweepLabel on $($targets.Count) host(s) ($authLabel), $threads thread(s)." }

    $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $threads, $iss, $Host)
    $pool.Open()
    $jobs = New-Object System.Collections.ArrayList
    foreach ($h in $targets) {
        $ps = [powershell]::Create(); $ps.RunspacePool = $pool
        [void]$ps.AddScript($script:SysadminSweepBlock)
        [void]$ps.AddArgument($h); [void]$ps.AddArgument($Credential); [void]$ps.AddArgument($auth)
        [void]$ps.AddArgument($attemptOffline); [void]$ps.AddArgument($ActionId); [void]$ps.AddArgument($days)
        [void]$ps.AddArgument($script:SysadminModulePath)
        [void]$jobs.Add([pscustomobject]@{ Host = $h; PS = $ps; Async = $ps.BeginInvoke(); StartedAt = $null })
    }

    $rows = New-Object System.Collections.ArrayList
    # audit 2026-07-24 (fable re-audit N1, P1): reference-type counter, because $emitResult is
    # invoked with & - a CHILD SCOPE - so a plain `$rk++` on an [int] wrote a child-scope local
    # and the parent never advanced. Every host therefore got _rk='r1', and since the view keys
    # rows by _rk (sysadmin.view.js) and the grid UPSERTS by it, each host silently REPLACED the
    # previous one: the stat cards said N hosts while the grid and the CSV export showed one.
    # For an admin-membership / cert-expiry audit that is a silently wrong answer, not a cosmetic
    # bug. remoteadmin.psm1 already carries this exact fix and comment; sysadmin was the twin.
    $rkBox = [pscustomobject]@{ N = 0 }

    # Emit every row a worker returned (>=1), each with a unique _rk, plus its report.
    $emitResult = {
        param($res)
        $resRows = @($res.Rows)
        if ($resRows.Count -eq 0) { $resRows = @(@{ Host = [string]$res.Host; Online = $false; Error = 'worker returned no rows' }) }
        foreach ($row in $resRows) {
            $rkBox.N++
            $row['_rk'] = ('r{0}' -f $rkBox.N)
            [void]$rows.Add($row)
            & $send (@{ type = 'row' } + $row)
        }
        $rpt = ''
        try { $rpt = [string]$res.Report } catch { $rpt = '' }
        if ($rpt) {
            # audit 2026-07-24: the uppercase state markers are matched case-SENSITIVELY
            # so the clean prose ('no reboot pending', 'no certs expiring within N day(s)')
            # is not ambered. audit 2026-07-25 (fable re-audit follow-up): that match ran
            # over the WHOLE line, hostname included, so a clean 'WS-ERROR-01' went amber
            # on its NAME - the decision now lives in Get-SysadminReportLevel, which looks
            # at the state portion of the line only (and is unit-tested).
            $lvl = Get-SysadminReportLevel -Report $rpt
            & $send @{ type = 'log'; level = $lvl; text = "[$(Get-Date -Format 'HH:mm:ss')] $rpt" }
        }
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
                    catch { $res = @{ Host = $j.Host; Online = $false; Error = "worker error: $($_.Exception.Message)"; Rows = @(); Report = "$($j.Host) : WORKER ERROR - $($_.Exception.Message)" } }
                    try { $j.PS.Dispose() } catch {}; $j.PS = $null
                    if ($null -eq $res) { $res = @{ Host = $j.Host; Online = $false; Error = 'worker returned no result'; Rows = @(); Report = "$($j.Host) : WORKER ERROR - no result" } }
                    & $emitResult $res
                    $done++; & $send @{ type = 'progress'; done = $done; total = $jobs.Count }
                }
            }
            # Per-host watchdog: abandon a host that overran its own clock.
            if ($done -lt $jobs.Count) {
                $nowPh = Get-Date
                foreach ($j in $jobs) {
                    if ($j.PS -and $j.StartedAt -and ($nowPh - $j.StartedAt).TotalSeconds -gt $perHostTimeout) {
                        try { [void]$j.PS.BeginStop($null, $null) } catch {}; $j.PS = $null
                        & $emitResult @{ Host = $j.Host; Online = $false; Error = "per-host timeout (${perHostTimeout}s)"; Rows = @(); Report = "$($j.Host) : TIMEOUT (${perHostTimeout}s) - possible remote read hang" }
                        $done++; & $send @{ type = 'progress'; done = $done; total = $jobs.Count }
                    }
                }
            }
            if ($done -lt $jobs.Count) {
                if ($cancelCheck -and (& $cancelCheck)) {
                    foreach ($j in $jobs) {
                        if ($j.PS) {
                            try { [void]$j.PS.BeginStop($null, $null) } catch {}; $j.PS = $null
                            & $emitResult @{ Host = $j.Host; Online = $false; Error = 'cancelled by operator'; Rows = @(); Report = "$($j.Host) : CANCELLED" }
                            $done++
                        }
                    }
                    & $send @{ type = 'log'; level = 'warn'; text = 'Run cancelled by operator; in-flight probes stopped.' }
                    break
                }
                Start-Sleep -Milliseconds 150
            }
        }
    } finally { try { $pool.Close(); $pool.Dispose() } catch {} }

    # Tally from the emitted rows.
    $online  = @($rows | Where-Object { $_.Online -eq $true } | ForEach-Object { [string]$_.Host } | Select-Object -Unique).Count
    $errored = @($rows | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.Error) } | ForEach-Object { [string]$_.Host } | Select-Object -Unique).Count
    $summary = @{ total = $targets.Count; hostsOnline = $online; hostsWithError = $errored; rows = $rows.Count }

    if ($ActionId -eq 'certexpiry-sweep') {
        $expiring = @($rows | Where-Object { $_.DaysLeft -is [int] -or ([string]$_.DaysLeft -match '^-?\d+$') })
        $expired  = @($expiring | Where-Object { ([int]$_.DaysLeft) -lt 0 })
        $summary['expiringCerts'] = $expiring.Count
        $summary['expiredCerts'] = $expired.Count
        & $send @{ type = 'log'; level = 'ok'; text = "Done. $($expiring.Count) expiring cert(s) ($($expired.Count) already expired) across $($targets.Count) host(s); $errored host(s) errored." }
    }
    elseif ($ActionId -eq 'rebootpending-sweep') {
        $pending = @($rows | Where-Object { $_.RebootPending -eq $true }).Count
        $summary['rebootPending'] = $pending
        & $send @{ type = 'log'; level = 'ok'; text = "Done. $pending host(s) reboot-pending of $($targets.Count); $errored host(s) errored." }
    }
    else {
        & $send @{ type = 'log'; level = 'ok'; text = "Done. $online host(s) online of $($targets.Count); $errored host(s) errored." }
    }

    & $send @{ type = 'status'; text = "Done. $($rows.Count) row(s) across $($targets.Count) host(s)." }
    return @{ rows = @($rows); summary = $summary }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction, Get-SysadminDaysLeft, Get-SysadminCleanMembers, Format-SysadminAdminList, Join-SysadminReasons, Get-SysadminIntParam, Get-SysadminReportLevel, Test-SysadminReachable, Get-SysadminRemoteBlock, New-SysadminProbeBlock
