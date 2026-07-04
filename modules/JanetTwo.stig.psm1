# =============================================================================
#  JanetTwo.stig.psm1  ->  STIG Checker (read-only STIG compliance scanner)
#
#  Net-new JANET TWO tool (no desktop twin), pattern-cloned from JanetTwo.c2c.psm1.
#  Fans out ONE consolidated read-only WinRM probe per host and scores a set of
#  Windows 10/11 member-server-safe STIG REGISTRY/POLICY checks defined in the
#  editable JanetLocal\stig-baseline.json. It CHANGES NOTHING (reads registry
#  only) and needs no admin session on the target beyond WinRM remoting rights.
#
#  Each rule is scored Compliant / Open / Error on each host:
#    Compliant - the registry value satisfies the rule's comparison (or is absent
#                and the rule's missingIs = Compliant).
#    Open      - the value is present but fails, OR is absent and missingIs = Open.
#    Error     - the value could not be read (each rule is wrapped in try/catch so
#                one bad read never aborts the probe).
#  Host verdict (computed admin-side): count Open / Error across the rules ->
#    COMPLIANT      = 0 Open and 0 Error
#    "<n> OPEN"     = >= 1 Open   (findings take priority; Detail lists CAT I/II)
#    CHECK ERRORS   = 0 Open but >= 1 Error
#    OFFLINE        = host unreachable (TCP 5985/445)
#
#  Two actions:
#    scan        - fleet scan; one row per host with Compliant/Open/Error counts
#                  and a verdict. Streams the full per-rule report to the log.
#    host-detail - single host; one row per rule (Rule/Title/Severity/Result/
#                  Detail) plus the streamed per-rule report. Read-only.
#
#  Baseline config (c2c/biosfirmware pattern): JanetLocal\stig-baseline.json read
#  FRESH each run, embedded defaults if it is missing/corrupt. The tool never
#  WRITES the file (no SMB atomic-write hazard) and works even if it is absent.
#
#  Read-only: destructive=false on both actions; emits NO audit rows (the server
#  keeps the automatic per-session START/END log).
#
#  Contract (server convention):
#    Get-JanetToolManifest                                       -> descriptors
#    Invoke-JanetToolAction -ActionId -Params -Credential -Emit  -> { rows; summary }
#  PowerShell 5.1 only. ASCII-only body; UTF-8 WITH BOM.
# =============================================================================

function Get-JanetToolManifest {
    @{
        id       = 'stig'
        name     = 'STIG Checker'
        version  = '1.0.1'
        category = 'Hardening'
        summary  = 'Read-only STIG compliance checker: fan out one consolidated WinRM probe per host and score a set of curated Windows 10/11 member-server-safe STIG registry/policy checks from the editable JanetLocal\stig-baseline.json. Each rule scores Compliant / Open / Error per host; the host verdict is COMPLIANT, N OPEN, CHECK ERRORS, or OFFLINE. Streams the full per-rule report to the activity log. Changes nothing.'
        actions  = @(
            @{
                id          = 'scan'
                label       = 'STIG Compliance Scan'
                description = 'Read-only STIG registry/policy scan. Per host, one consolidated WinRM probe reads every rule in JanetLocal\stig-baseline.json and scores it Compliant / Open / Error, then returns per-host counts and a one-word verdict: COMPLIANT (0 open, 0 error), N OPEN (one or more findings), CHECK ERRORS (a rule could not be read), or OFFLINE. The full per-rule report ([COMPLIANT]/[OPEN]/[ERROR] lines with CAT severity) streams to the activity log. Changes NOTHING.'
                kind        = 'stream-table'
                destructive = $false
                columns     = @('Host','Ping','Compliant','Open','Errors','Verdict','Detail')
                inputs      = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts (1-32)'; type='int'; required=$false; default=16 }
                )
            }
            @{
                id          = 'host-detail'
                label       = 'Host Rule Detail'
                description = 'Read-only per-rule breakdown for a SINGLE host: runs the same consolidated probe and returns one row per STIG rule (Rule id, Title, CAT severity, Result, Detail). The full per-rule report also streams to the activity log. Changes NOTHING.'
                kind        = 'stream-table'
                destructive = $false
                columns     = @('Rule','Title','Severity','Result','Detail')
                inputs      = @(
                    @{ name='host'; label='Host'; type='string'; required=$true },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$true }
                )
            }
        )
    }
}

# --- Baseline config --------------------------------------------------------
# Embedded defaults (a small safe subset) so a scan still runs if the JanetLocal
# file is missing/corrupt. Operators maintain the full ~30-rule catalog by editing
# JanetLocal\stig-baseline.json; the tool never writes the file.
function Get-StigBaselineDefaults {
    @(
        @{ id='SMB1-SERVER-DISABLED'; title='SMBv1 server protocol disabled'; severity='CAT I'; hive='HKLM'; path='SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; value='SMB1'; comparison='eq'; expected=0; missingIs='Open'; note='SMBv1 must be disabled.' },
        @{ id='LMCOMPAT-LEVEL-5'; title='LAN Manager authentication level NTLMv2 only'; severity='CAT II'; hive='HKLM'; path='SYSTEM\CurrentControlSet\Control\Lsa'; value='LmCompatibilityLevel'; comparison='eq'; expected=5; missingIs='Open'; note='Send NTLMv2 only; refuse LM and NTLM.' },
        @{ id='NO-LM-HASH'; title='Do not store LAN Manager hash'; severity='CAT I'; hive='HKLM'; path='SYSTEM\CurrentControlSet\Control\Lsa'; value='NoLMHash'; comparison='eq'; expected=1; missingIs='Open'; note='Weak LM hash must never be stored.' },
        @{ id='UAC-ENABLE-LUA'; title='User Account Control enabled'; severity='CAT I'; hive='HKLM'; path='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; value='EnableLUA'; comparison='eq'; expected=1; missingIs='Open'; note='UAC boundary must be on.' }
    )
}

function Get-StigBaselinePath { Join-Path $PSScriptRoot '..\JanetLocal\stig-baseline.json' }

# Normalize one raw baseline entry (from JSON or defaults) into a clean typed
# hashtable, or $null if it is unusable. Enforces every field the probe relies on
# so no rule is ambiguous (comparison/missingIs defaulted + validated).
function ConvertTo-StigRule {
    param($Raw)
    if ($null -eq $Raw) { return $null }
    $get = {
        param($name)
        if ($Raw -is [hashtable]) { if ($Raw.ContainsKey($name)) { return $Raw[$name] } else { return $null } }
        $p = $Raw.PSObject.Properties[$name]; if ($p) { return $p.Value } else { return $null }
    }
    $id    = [string](& $get 'id')
    $hive  = ([string](& $get 'hive')).ToUpper()
    $path  = [string](& $get 'path')
    $value = [string](& $get 'value')
    if ([string]::IsNullOrWhiteSpace($id))   { return $null }
    if ($hive -ne 'HKLM' -and $hive -ne 'HKCU') { return $null }
    if ([string]::IsNullOrWhiteSpace($path))  { return $null }
    if ([string]::IsNullOrWhiteSpace($value)) { return $null }

    $comparison = ([string](& $get 'comparison')).ToLower()
    if ($comparison -ne 'eq' -and $comparison -ne 'ge' -and $comparison -ne 'exists') { $comparison = 'eq' }

    $missingIs = ([string](& $get 'missingIs'))
    if ($missingIs -match '(?i)^compliant$') { $missingIs = 'Compliant' } else { $missingIs = 'Open' }

    $title = [string](& $get 'title'); if ([string]::IsNullOrWhiteSpace($title)) { $title = $id }
    $sev   = [string](& $get 'severity'); if ([string]::IsNullOrWhiteSpace($sev)) { $sev = 'CAT II' }
    $note  = [string](& $get 'note')

    $expected = & $get 'expected'
    $oneOfRaw = & $get 'expectedOneOf'
    $oneOf = @()
    if ($oneOfRaw) { $oneOf = @(@($oneOfRaw) | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' }) }

    return @{
        id=$id; title=$title; severity=$sev; hive=$hive; path=$path; value=$value;
        comparison=$comparison; expected=([string]$expected); expectedOneOf=$oneOf;
        missingIs=$missingIs; note=$note
    }
}

# Read the editable JanetLocal baseline fresh; returns @{ Rules=@(...); Source='...' }.
# Any problem (missing/corrupt/empty/no valid rules) falls back to the embedded
# defaults - a bad JSON never breaks a scan. Read-only: never writes the file.
function Get-StigBaseline {
    $fallback = @(@(Get-StigBaselineDefaults) | ForEach-Object { ConvertTo-StigRule $_ } | Where-Object { $_ })
    try {
        $p = Get-StigBaselinePath
        if (-not (Test-Path -LiteralPath $p)) { return @{ Rules=$fallback; Source='embedded defaults (no JanetLocal\stig-baseline.json)' } }
        $raw = Get-Content -LiteralPath $p -Raw -ErrorAction Stop
        if ($null -eq $raw) { $raw = '' }
        if ($raw.Length -gt 0 -and [int]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }  # defensive BOM strip
        if ([string]::IsNullOrWhiteSpace($raw)) { return @{ Rules=$fallback; Source='embedded defaults (baseline file empty)' } }
        $obj = $raw | ConvertFrom-Json -ErrorAction Stop
        if (-not $obj) { return @{ Rules=$fallback; Source='embedded defaults (baseline parsed empty)' } }
        $rawChecks = $null
        if ($obj.PSObject.Properties['checks']) { $rawChecks = $obj.checks } else { $rawChecks = $obj }
        $rules = @(@($rawChecks) | ForEach-Object { ConvertTo-StigRule $_ } | Where-Object { $_ })
        if ($rules.Count -eq 0) { return @{ Rules=$fallback; Source='embedded defaults (baseline had no valid checks)' } }
        return @{ Rules=$rules; Source="JanetLocal\stig-baseline.json ($($rules.Count) checks)" }
    } catch { return @{ Rules=$fallback; Source="embedded defaults (baseline read error: $($_.Exception.Message))" } }
}

# --- Per-host probe worker (runs in a pool runspace; no module scope here) ---
# Returns @{ Host; Ping; Status; Detail; Compliant; Open; Errors; Ok; Report; Rules }.
# All rules run inside ONE Invoke-Command round-trip; the verdict is computed here.
$script:StigProbeBlock = {
    param([string]$Computer, $Cred, [string]$Auth, [bool]$AttemptOffline, $Rules)

    $r = @{ Host=$Computer; Ping=''; Status=''; Detail=''; Compliant=0; Open=0; Errors=0; Ok=$false; Report=''; Rules=@() }

    # Reachability pre-check: pure-TCP probe (AFNET-safe; never ICMP). WinRM 5985
    # then SMB 445, 1500ms connect timeout, break on first connect (c2c idiom).
    $reachable = $false
    foreach ($port in 5985,445) {
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) { $reachable = $true; $r.Ping = "TCP $port" }
        } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
        if ($reachable) { break }
    }
    if (-not $reachable) {
        $r.Ping = 'Unreachable'
        if (-not $AttemptOffline) {
            $r.Status = 'OFFLINE'; $r.Detail = 'No TCP on 5985/445 (1.5s timeouts). Enable "Attempt even if offline" to force.'
            return $r
        }
    }

    # Marshal the rules into a plain [object[]] of hashtables so they cross the
    # WinRM ArgumentList boundary cleanly (drop any null the boundary might inject).
    $ruleArr = @(@($Rules) | Where-Object { $_ })

    $wsOpt = New-PSSessionOption -OperationTimeout 180000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
    $splat = @{ ComputerName=$Computer; SessionOption=$wsOpt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    $sess = $null
    try { $sess = New-PSSession @splat } catch { $r.Status = 'ERROR'; $r.Detail = "Session: $($_.Exception.Message)"; return $r }

    # ---- The consolidated read-only probe: every STIG rule in one round-trip. ----
    $probeSb = {
        param($Rules)
        $rules = @(@($Rules) | Where-Object { $_ })
        $out = New-Object System.Collections.ArrayList

        # Read one registry value. Returns @{ Found=$bool; KeyExists=$bool; Value=<raw> }
        # or THROWS on a genuine read failure (access-denied/other) so the per-rule
        # catch scores Error instead of silently treating an unreadable key as 'absent'.
        $readVal = {
            param($hive, $path, $name)
            $root = if ($hive -eq 'HKCU') { 'HKCU:' } else { 'HKLM:' }
            $full = $root + '\' + $path
            # Open the key with -ErrorAction Stop: ItemNotFound = key truly absent
            # (scored via missingIs); any other exception (SecurityException / access-
            # denied) propagates to the per-rule catch and scores Error. Test-Path was
            # wrong here - it returns $false on access-denied, hiding the failure.
            try {
                [void](Get-Item -LiteralPath $full -ErrorAction Stop)
            } catch [System.Management.Automation.ItemNotFoundException] {
                return @{ Found=$false; KeyExists=$false; Value=$null }
            }
            # Key exists: read the whole property bag (no -Name, which is a wildcard
            # parameter that would glob a value name containing * ? or [ ]). A read
            # failure here (-ErrorAction Stop) also rethrows -> Error, not 'absent'.
            $item = Get-ItemProperty -LiteralPath $full -ErrorAction Stop
            $prop = $item.PSObject.Properties[$name]
            if ($null -eq $prop) { return @{ Found=$false; KeyExists=$true; Value=$null } }
            return @{ Found=$true; KeyExists=$true; Value=$prop.Value }
        }

        # Numeric-or-string comparison helper.
        $asLong = {
            param($v, [ref]$ok)
            $n = [long]0
            $ok.Value = [long]::TryParse(([string]$v).Trim(), [ref]$n)
            return $n
        }

        foreach ($rule in $rules) {
            $id    = [string]$rule['id']
            $title = [string]$rule['title']
            $sev   = [string]$rule['severity']
            $hive  = [string]$rule['hive']
            $path  = [string]$rule['path']
            $vname = [string]$rule['value']
            $cmp   = [string]$rule['comparison']
            $exp   = [string]$rule['expected']
            $oneOf = @($rule['expectedOneOf'])
            $missingIs = [string]$rule['missingIs']

            $result = 'Error'; $detail = ''
            try {
                $rv = & $readVal $hive $path $vname
                if (-not $rv.Found) {
                    $result = if ($missingIs -eq 'Compliant') { 'Compliant' } else { 'Open' }
                    $absent = if ($rv.KeyExists) { 'value not set' } else { 'key absent' }
                    $detail = "$hive\...\$vname $absent (missing => $result)"
                } else {
                    $val = $rv.Value
                    # REG_MULTI_SZ (string[]) / REG_BINARY (byte[]) are not scalar-comparable;
                    # [string] would silently $OFS-join them. Score Error, not a bogus verdict.
                    if ($val -is [array]) { throw 'unsupported registry type (MULTI_SZ/BINARY)' }
                    $valTxt = [string]$val
                    $pass = $false
                    if ($cmp -eq 'exists') {
                        $pass = $true
                        $detail = "$vname present = '$valTxt'"
                    } elseif ($oneOf.Count -gt 0) {
                        foreach ($o in $oneOf) { if (([string]$o).Trim() -eq $valTxt.Trim()) { $pass = $true; break } }
                        $detail = "$vname = '$valTxt' (expected one of: $($oneOf -join ', '))"
                    } elseif ($cmp -eq 'ge') {
                        $okA = $false; $okB = $false
                        $na = & $asLong $val ([ref]$okA); $nb = & $asLong $exp ([ref]$okB)
                        if ($okA -and $okB) { $pass = ($na -ge $nb) } else { $pass = $false }
                        $detail = "$vname = '$valTxt' (expected >= $exp)"
                    } else {
                        $okA = $false; $okB = $false
                        $na = & $asLong $val ([ref]$okA); $nb = & $asLong $exp ([ref]$okB)
                        if ($okA -and $okB) { $pass = ($na -eq $nb) } else { $pass = ($valTxt.Trim() -eq ([string]$exp).Trim()) }
                        $detail = "$vname = '$valTxt' (expected $exp)"
                    }
                    $result = if ($pass) { 'Compliant' } else { 'Open' }
                }
            } catch {
                $result = 'Error'; $detail = "read error: $($_.Exception.Message)"
            }

            [void]$out.Add([pscustomobject]@{ Id=$id; Title=$title; Severity=$sev; Result=$result; Detail=$detail })
        }

        return @{ RemoteName = $env:COMPUTERNAME; Rules = @($out) }
    }

    try {
        $probe = Invoke-Command -Session $sess -ScriptBlock $probeSb -ArgumentList (,$ruleArr) -ErrorAction Stop
    } catch {
        $r.Status = 'ERROR'; $r.Detail = "Probe: $($_.Exception.Message)"
        Remove-PSSession $sess -ErrorAction SilentlyContinue
        return $r
    } finally { if ($sess) { Remove-PSSession $sess -ErrorAction SilentlyContinue } }

    # DNS-mismatch guard (read-only soft-warn, c2c idiom): a wrong box would report
    # the wrong compliance. Session name compare, never a PTR lookup.
    $actualName  = ([string]$probe.RemoteName).Trim()
    # An IPv4 target has no shortname to compare ('192.168.1.50' -> '192'), so skip the
    # name-compare for IP tokens - otherwise every IP-addressed host is falsely discarded.
    $targetIsIp  = ($Computer -match '^\d{1,3}(\.\d{1,3}){3}$')
    $targetShort = ($Computer -split '\.')[0]
    if (-not $targetIsIp -and $actualName -and ($actualName.ToUpper() -ne $targetShort.ToUpper())) {
        $r.Status = 'DNS MISMATCH'; $r.Detail = "dialed '$targetShort' but remote is '$actualName' - skipped (would report the wrong machine)"
        return $r
    }

    $ruleResults = @($probe.Rules)
    $r.Rules = $ruleResults
    if ($ruleResults.Count -eq 0) { $r.Status = 'ERROR'; $r.Detail = 'probe returned no rules'; return $r }

    # Verdict: tally Compliant / Open / Error.
    $openRules = @($ruleResults | Where-Object { $_.Result -eq 'Open' })
    $errRules  = @($ruleResults | Where-Object { $_.Result -eq 'Error' })
    $compCount = @($ruleResults | Where-Object { $_.Result -eq 'Compliant' }).Count
    $openCount = $openRules.Count
    $errCount  = $errRules.Count
    $r.Compliant = $compCount; $r.Open = $openCount; $r.Errors = $errCount

    if     ($openCount -ge 1) { $r.Status = "$openCount OPEN";   $r.Ok = $false }
    elseif ($errCount  -ge 1) { $r.Status = 'CHECK ERRORS';      $r.Ok = $false }
    else                      { $r.Status = 'COMPLIANT';         $r.Ok = $true  }

    $parts = New-Object System.Collections.ArrayList
    if ($openCount -ge 1) {
        $cat1 = @($openRules | Where-Object { [string]$_.Severity -match '(?i)CAT\s*I(\b|[^I])' -and [string]$_.Severity -notmatch '(?i)CAT\s*II' }).Count
        $catList = @($openRules | ForEach-Object { [string]$_.Id })
        $shown = @($catList | Select-Object -First 6)
        $more = if ($catList.Count -gt 6) { " (+$($catList.Count - 6) more)" } else { '' }
        [void]$parts.Add("$openCount open: $($shown -join ', ')$more")
        if ($cat1 -gt 0) { [void]$parts.Add("$cat1 CAT I") }
    }
    if ($errCount -ge 1) { [void]$parts.Add("$errCount error: $(@($errRules | ForEach-Object { [string]$_.Id } | Select-Object -First 4) -join ', ')") }
    if ($openCount -eq 0 -and $errCount -eq 0) { [void]$parts.Add("all $compCount rule(s) compliant") }
    $r.Detail = ($parts -join ' | ')

    # Full per-rule colour-tagged report ([COMPLIANT]/[OPEN]/[ERROR]) the view colours.
    $rptLines = foreach ($c in $ruleResults) { '[{0}] {1} {2}: {3}' -f ([string]$c.Result).ToUpper(), ('{0,-7}' -f [string]$c.Severity), ([string]$c.Id), ([string]$c.Detail) }
    $r.Report = ($rptLines -join "`r`n")
    return $r
}

# Stream a worker result's per-rule report to the activity log (shared by both
# actions). Colours [COMPLIANT] green / [OPEN] red / [ERROR] amber.
function Send-StigReport {
    param($Send, $Res)
    $rpt = ''
    try { $rpt = [string]$Res.Report } catch { $rpt = '' }
    if (-not $rpt) { return }
    & $Send @{ type='log'; level='info'; text="----- $([string]$Res.Host) : $([string]$Res.Status) -----" }
    foreach ($ln in ($rpt -split "`r?`n")) {
        if ([string]::IsNullOrWhiteSpace($ln)) { continue }
        $lvl = 'info'
        if     ($ln -match '^\s*\[COMPLIANT\]') { $lvl = 'ok' }
        elseif ($ln -match '^\s*\[OPEN\]')      { $lvl = 'error' }
        elseif ($ln -match '^\s*\[ERROR\]')     { $lvl = 'warn' }
        & $Send @{ type='log'; level=$lvl; text=$ln }
    }
}

function Invoke-JanetToolAction {
    param(
        [string]$ActionId,
        [hashtable]$Params,
        [System.Management.Automation.PSCredential]$Credential,
        [scriptblock]$Emit
    )
    $send = { param($e) if ($Emit) { & $Emit $e } }

    if ($ActionId -ne 'scan' -and $ActionId -ne 'host-detail') {
        & $send @{ type='error'; text="Unknown action '$ActionId'." }
        return @{ rows=@(); summary=@{} }
    }

    # Load the baseline fresh (works even if the file is missing).
    $baseline = Get-StigBaseline
    $rules    = @($baseline.Rules)
    if ($rules.Count -eq 0) {
        & $send @{ type='error'; text="No STIG rules available (baseline: $($baseline.Source))." }
        return @{ rows=@(); summary=@{ total=0; source=$baseline.Source } }
    }

    $attemptOffline = $false
    if ($null -ne $Params['attemptOffline']) {
        $av = $Params['attemptOffline']
        $attemptOffline = if ($av -is [bool]) { [bool]$av } else { ("$av" -match '^(?i:true|1|yes|on)$') }
    }
    $auth = if ($Credential) { 'Negotiate' } else { 'Default' }
    $authLabel = if ($Credential) { "as $($Credential.UserName)" } else { 'current session' }

    # ---------------------------------------------------------------- host-detail
    if ($ActionId -eq 'host-detail') {
        $h = ([string]$Params['host']).Trim()
        if (-not ($h -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$')) {
            & $send @{ type='log'; level='warn'; text="Invalid host '$h'." }
            return @{ rows=@(); summary=@{ total=0 } }
        }
        if ($null -eq $Params['attemptOffline']) { $attemptOffline = $true }  # single-host detail defaults to forcing
        & $send @{ type='status'; text="STIG rule detail on $h ($($rules.Count) rules)... (baseline: $($baseline.Source))" }
        & $send @{ type='log'; level='info'; text="[$(Get-Date -Format 'HH:mm:ss')] START STIG host-detail on $h ($authLabel). Baseline: $($baseline.Source)." }

        $res = & $script:StigProbeBlock $h $Credential $auth $attemptOffline $rules
        Send-StigReport $send $res

        $rows = New-Object System.Collections.ArrayList
        $ruleResults = @($res.Rules)
        if ($ruleResults.Count -eq 0) {
            & $send @{ type='log'; level='warn'; text="No per-rule results for ${h}: $([string]$res.Status) - $([string]$res.Detail)" }
            & $send @{ type='status'; text="Done. $h : $([string]$res.Status)." }
            return @{ rows=@(); summary=@{ total=0; host=$h; status=[string]$res.Status; detail=[string]$res.Detail; source=$baseline.Source } }
        }
        $idx = 0
        foreach ($c in $ruleResults) {
            $idx++
            $row = @{ _rk="$idx|$([string]$c.Id)"; Rule=[string]$c.Id; Title=[string]$c.Title; Severity=[string]$c.Severity; Result=[string]$c.Result; Detail=[string]$c.Detail }
            [void]$rows.Add($row); & $send (@{ type='row' } + $row)
        }
        $comp = @($ruleResults | Where-Object { $_.Result -eq 'Compliant' }).Count
        $open = @($ruleResults | Where-Object { $_.Result -eq 'Open' }).Count
        $err  = @($ruleResults | Where-Object { $_.Result -eq 'Error' }).Count
        & $send @{ type='log'; level=($(if ($open) { 'warn' } else { 'ok' })); text="$h : $comp compliant, $open open, $err error of $($ruleResults.Count) rule(s)." }
        & $send @{ type='status'; text="Done. $h : $comp compliant / $open open / $err error." }
        return @{ rows=@($rows); summary=@{ total=$ruleResults.Count; host=$h; compliant=$comp; open=$open; errors=$err; status=[string]$res.Status; source=$baseline.Source } }
    }

    # ---------------------------------------------------------------- scan
    # Operator-cancel bridge (server injects $Params['__job']).
    $cancelJob = $null
    if ($Params -and $Params.ContainsKey('__job')) { $cancelJob = $Params['__job'] }
    $cancelCheck = { if ($cancelJob) { try { [bool]$cancelJob['Cancel'] } catch { $false } } else { $false } }.GetNewClosure()

    # Targets: accept only bare host/IPv4 tokens; drop UNC/URL/junk before any WinRM call.
    $targets = @(([string]$Params['targets']) -split '[\r\n,;\t ]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ -and ($_ -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$') } | Select-Object -Unique)
    if ($targets.Count -eq 0) {
        & $send @{ type='log'; level='warn'; text='No valid targets.' }
        return @{ rows=@(); summary=@{ total=0 } }
    }

    $threads = 16
    # Parse into a temp so a garbage value keeps the default 16, not TryParse's 0 (->1).
    if ($Params['threads']) { $tParsed = 0; if ([int]::TryParse([string]$Params['threads'], [ref]$tParsed)) { $threads = $tParsed } }
    $threads = [Math]::Max(1, [Math]::Min(32, $threads))
    $perHostTimeout = 200  # a read-only registry probe that runs this long = a wedged remote read

    & $send @{ type='status'; text="STIG scan on $($targets.Count) host(s), $($rules.Count) rules, $threads thread(s)... (baseline: $($baseline.Source))" }
    & $send @{ type='log'; level='info'; text="[$(Get-Date -Format 'HH:mm:ss')] START STIG scan on $($targets.Count) host(s) ($authLabel), $threads thread(s), $($rules.Count) rules. Baseline: $($baseline.Source)." }

    $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $threads, $iss, $Host)
    $pool.Open()
    # Seed Queued rows so the operator sees the whole target list immediately.
    foreach ($h in $targets) { & $send (@{ type='row' } + @{ Host=$h; Ping=''; Compliant=''; Open=''; Errors=''; Verdict='Queued'; Detail='waiting for a runspace...' }) }
    $jobs = New-Object System.Collections.ArrayList
    foreach ($h in $targets) {
        $ps = [powershell]::Create(); $ps.RunspacePool = $pool
        [void]$ps.AddScript($script:StigProbeBlock)
        [void]$ps.AddArgument($h); [void]$ps.AddArgument($Credential); [void]$ps.AddArgument($auth); [void]$ps.AddArgument($attemptOffline); [void]$ps.AddArgument($rules)
        [void]$jobs.Add([pscustomobject]@{ Host=$h; PS=$ps; Async=$ps.BeginInvoke(); StartedAt=$null })
    }

    $rows = New-Object System.Collections.ArrayList

    # Build a row from a worker result, emit it, and stream its per-rule report.
    $emitResult = {
        param($res)
        $verdict = [string]$res.Status
        # Normalize host-level evaluation failures to a status the shared view colours
        # + counts: raw ERROR / DNS MISMATCH -> CHECK ERRORS. Detail keeps the reason.
        if ($verdict -eq 'ERROR' -or $verdict -eq 'DNS MISMATCH') { $verdict = 'CHECK ERRORS' }
        $row = @{
            Host=[string]$res.Host; Ping=[string]$res.Ping;
            Compliant=[string]$res.Compliant; Open=[string]$res.Open; Errors=[string]$res.Errors;
            Verdict=$verdict; Detail=[string]$res.Detail
        }
        [void]$rows.Add($row)
        & $send (@{ type='row' } + $row)
        Send-StigReport $send $res
    }

    $done = 0
    try {
        while ($done -lt $jobs.Count) {
            foreach ($j in $jobs) {
                if ($j.PS -and -not $j.StartedAt -and $j.PS.InvocationStateInfo.State -eq 'Running') { $j.StartedAt = Get-Date }
                if ($j.PS -and $j.Async.IsCompleted) {
                    $res = $null
                    try { $res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 }
                    catch { $res = @{ Host=$j.Host; Ping=''; Status='ERROR'; Detail="worker error: $($_.Exception.Message)"; Compliant=0; Open=0; Errors=0; Ok=$false; Report='' } }
                    try { $j.PS.Dispose() } catch {}; $j.PS = $null
                    if ($null -eq $res) { $res = @{ Host=$j.Host; Ping=''; Status='ERROR'; Detail='worker returned no result'; Compliant=0; Open=0; Errors=0; Ok=$false; Report='' } }
                    & $emitResult $res
                    $done++; & $send @{ type='progress'; done=$done; total=$jobs.Count }
                }
            }
            # Per-host watchdog: abandon a host that overran its own clock (wedged remote read).
            if ($done -lt $jobs.Count) {
                $nowPh = Get-Date
                foreach ($j in $jobs) {
                    if ($j.PS -and $j.StartedAt -and ($nowPh - $j.StartedAt).TotalSeconds -gt $perHostTimeout) {
                        try { [void]$j.PS.BeginStop($null, $null) } catch {}; $j.PS = $null
                        & $emitResult @{ Host=$j.Host; Ping=''; Status='ERROR'; Detail="per-host timeout (${perHostTimeout}s) - possible remote read hang"; Compliant=0; Open=0; Errors=0; Ok=$false; Report='' }
                        $done++; & $send @{ type='progress'; done=$done; total=$jobs.Count }
                    }
                }
            }
            if ($done -lt $jobs.Count) {
                if ($cancelCheck -and (& $cancelCheck)) {
                    foreach ($j in $jobs) {
                        if ($j.PS) {
                            try { [void]$j.PS.BeginStop($null, $null) } catch {}; $j.PS = $null
                            & $emitResult @{ Host=$j.Host; Ping=''; Status='Cancelled'; Detail='cancelled by operator'; Compliant=0; Open=0; Errors=0; Ok=$false; Report='' }
                            $done++
                        }
                    }
                    & $send @{ type='log'; level='warn'; text='Run cancelled by operator; in-flight probes stopped.' }
                    break
                }
                Start-Sleep -Milliseconds 150
            }
        }
    } finally { try { $pool.Close(); $pool.Dispose() } catch {} }

    # Tally from the emitted rows (each row carries its Verdict).
    $compliant = @($rows | Where-Object { $_.Verdict -eq 'COMPLIANT' }).Count
    $open      = @($rows | Where-Object { $_.Verdict -match '(?i)\bOPEN$' }).Count
    $chkErr    = @($rows | Where-Object { $_.Verdict -eq 'CHECK ERRORS' }).Count
    $offline   = @($rows | Where-Object { $_.Verdict -eq 'OFFLINE' }).Count
    $other     = $targets.Count - $compliant - $open - $chkErr - $offline
    $pct       = if ($targets.Count -gt 0) { [math]::Round(($compliant / $targets.Count) * 100, 1) } else { 0 }

    & $send @{ type='log'; level='ok'; text="STIG scan - $pct% COMPLIANT ($compliant/$($targets.Count)). OPEN: $open, CHECK ERRORS: $chkErr, OFFLINE: $offline, Other: $other." }
    & $send @{ type='status'; text="Done. $compliant compliant, $open with open findings, $chkErr check-errors, $offline offline of $($targets.Count)." }
    return @{ rows=@($rows); summary=@{ total=$targets.Count; compliant=$compliant; open=$open; checkErrors=$chkErr; offline=$offline; other=$other; compliantPct=$pct; rules=$rules.Count; source=$baseline.Source } }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction
