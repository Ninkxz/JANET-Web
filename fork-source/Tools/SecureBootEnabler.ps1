#Requires -Version 5.1
<#
.SYNOPSIS
    J.A.N.E.T. // Secure Boot Enabler.
.DESCRIPTION
    Deploys a Secure Boot enable payload to up to 50 remote machines
    simultaneously via CIM/DCOM scheduled task (SYSTEM context). Polls
    a result file on the remote machine's C$\Windows\Temp share. No
    WinRM dependency.

    Supported OEMs: Dell, HP, Lenovo.
.NOTES
    v1.5.0 - 2026-06-06 - Multi-agent security + correctness review fixes.
             SECURITY:
             * Hostname code-injection-as-SYSTEM closed. The v1.3 fix escaped
               the BIOS password but the operator-supplied hostname was still
               interpolated unescaped into the single-quoted $ResultPath literal
               that runs as SYSTEM - a name with a single quote injected code on
               every target. Now hostnames are allow-list validated (^[A-Za-z0-9._-]+$)
               at the Run button AND the result path is single-quote-escaped.
             * Password no longer shipped in the scheduled-task command line.
               -EncodedCommand is reversible Base64 and the task XML is readable
               by any local user. The payload is now written to a SYSTEM+Admins-
               only (icacls, well-known SIDs) file on the target and run with
               -File; the payload self-deletes it, and the launcher + close
               handler remove it as backstops.
             * BIOS passwords containing comma / quote / backtick are rejected at
               input (they corrupt the comma-delimited Lenovo/HP WMI argument).
             * Inherited-credential validation no longer leaves the decrypted
               domain password materialized on the heap (captures a boolean, then
               nulls the NetworkCredential immediately; keeps smartcard detection).
             FIRMWARE SAFETY:
             * False-success fixed: Dell/HP/Lenovo non-zero return codes (commonly
               a wrong BIOS password) were reported as green Success. Each Enable-*
               now surfaces a non-success code as an Error so it is classified
               correctly; the Lenovo SaveBiosSettings commit return is captured
               (was discarded, so a refused commit that reverts on reboot read as
               Success); HP guards a null target value / multiple SB settings; Dell
               flags a Status-0-but-no-change read-back.
             * Brick-safety precheck: before any OEM write the payload verifies
               UEFI firmware mode + a GPT system/boot disk and SKIPs anything it
               cannot confirm safe, rather than risk leaving a Legacy/CSM/MBR box
               unbootable.
             RELIABILITY:
             * Result-file polling reads with -LiteralPath, accepts only a parse
               with the expected fields (no half-written acceptance), does a final
               read after the deadline (no false Timeout on a host that finished
               last second), and distinguishes corrupt-result / C$-access-denied /
               genuine-timeout instead of one generic message.
             * Dry-Run mode is snapshotted at Run and the mode/concurrency/password
               inputs are locked during a run, so toggling Dry Run mid-run can no
               longer mix real firmware writes and previews in one batch.
             * Dry-run previews are no longer logged to JANET as VulnPatched/Failure
               (was inflating the session Failures rollup with phantom failures).
             * Orphaned SYSTEM task cleanup: the task name is generated in the
               parent and tracked, so closing the tool mid-run best-effort
               unregisters in-flight tasks + removes temp files (a force-killed
               job's finally does not run).
    v1.4.3 - 2026-05-10 - JANET replay filter widened to *_detail*.csv /
                          *_usage*.csv so schema-rotation sister files
                          (created when the legacy file is persistently
                          locked) are drained on next launch instead of
                          stranded.
    v1.4.2 - 2026-05-08 - JANET centralized-logging schema cleanup (single
                          SessionEnd rollup row; Snapshot rows retired) and
                          the WPT-themed Closing Notes prompt rolled across
                          the suite.
    v1.4.1 - 2026-04-25 - Added JANET centralized logging. Per-host EnableSecureBoot
                          rows go to \\dm-tn-01\sh-usafe-automation$\JANET\Logs\SecureBoot\<YYYY-MM>_detail.csv;
                          rollup row per session goes to <YYYY-MM>_usage.csv at the log root.
                          JANET closing-notes dialog captures ASI+notes on form close.
                          Spec: docs/superpowers/specs/2026-04-25-janet-centralized-logging-design.md
    v1.3 - April 2026 - Hardening + HP After-column fix. Validated
           against a mixed Dell/HP/Lenovo test ring (BIOS password
           literal "password"): Dell reported live "Disabled ->
           Enabled", HP reported "Disable -> Enable (pending reboot)"
           with a post-reboot pre-check correctly classifying the
           host as Skipped on the next run, Lenovo committed and
           persisted through reboot. Experimental tag removed.
           Changes:
           * HP: HP_BIOSEnumeration.CurrentValue reflects the BOOTED
             setting, not staged NVRAM. Immediate read-back showed
             "Disable -> Disable" with SetResult=Successful (return
             code 0). Enable-HPSecureBoot now treats return=0 as
             authoritative and reports the staged target with a
             "(pending reboot)" suffix. Non-zero returns still fall
             back to the raw read so real failures stay visible.
           * Security: BIOS password is now single-quote-escaped
             before it is baked into the encoded payload. Previously
             a password containing a single quote would break the
             generated source and could inject arbitrary code that
             would run as SYSTEM on every target.
           * Dry-run now uses DCOM via New-CimSession (same transport
             as live mode) instead of default WSMan. A green dry-run
             is now actually predictive of live reachability.
           * Scheduled-task cleanup moved to a finally block so an
             Unregister is guaranteed even if Start-ScheduledTask
             throws or the result-file polling window expires.
           * OS precheck: Supported=$null (generic Confirm-
             SecureBootUEFI failure, e.g. permissions) is now a hard
             stop instead of silently falling through to a BIOS write.
           * Credential inherit guards against smartcard-derived
             PSCredential objects whose password SecureString is null.
           * Form-close path now disposes PollTimer + pulse timers
             and removes only this tool's jobs (not unrelated ones).
           * MinimumSize raised to 1200x680 so the right-column cards
             no longer clip at the floor width.
    v1.2 - April 2026 - GUI restyle to the J.A.N.E.T. Purple + Gold
           theme (Cascadia Mono, corner-bracket cards, stripe CTA,
           live pulse indicator, dark immersive title bar). Payload
           logic, scheduled-task plumbing, credential handling, and
           polling timer behaviour preserved byte-for-byte from v1.1.
    v1.1 - Inherited JANET launcher credential via $env:JANET_CRED_FILE.
    v1.0 - Initial release.

    Fixes carried from v1.0:
      - Win32_ComputerSystem via Get-CimInstance (no deprecated alias)
      - HP: $BiosConfig/$BIOSConfig case mismatch, $sbSetting scope
      - Lenovo: Lenovo_SaveBiosSettings commit
      - Dell: $pwd built-in collision fixed ($pwdBytes)
      - All: -ErrorAction Stop so errors surface in the result JSON
      - Remote exec via DCOM scheduled task, C$ share result file
    BIOS password is injected directly into the encoded payload string.
    Avoid quotes/backticks in the BIOS password.
#>

Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.Drawing        -ErrorAction SilentlyContinue
try { [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false) } catch {}
try { [System.Windows.Forms.Application]::EnableVisualStyles() } catch {}

###############################################################################
###                       JANET CENTRALIZED LOGGING                         ###
###############################################################################
## Added in v1.4.1. See spec:
##   J.A.N.E.T/docs/superpowers/specs/2026-04-25-janet-centralized-logging-design.md
## Self-contained — no external module imports. Single source of truth is
## $JanetLogRoot. Falls back to %USERPROFILE%\Documents\SecureBoot\ when share
## is unreachable; replays orphan rows on next launch with the share back up.
$JanetSecureBootVersion = '1.5.0'

# === BEGIN JANET LOGGING BLOCK (paste from here) ===
$JanetLogRoot = '\\dm-tn-01\sh-usafe-automation$\JANET\Logs'

$script:JanetSession   = $null
$script:JanetNetworkOk = $false

## Closure-safe getter — closures created with .GetNewClosure() under StrictMode 3
## cannot reliably resolve $script:Foo. Helpers used from inside closures must
## be declared at global scope so they are always visible.
function global:Get-JanetSession { return $script:JanetSession }

## X-block flag. Initialized $false in the form builder; set $true only by
## the Close Tool button handler. The FormClosing handler cancels any close
## that arrives without the flag set (X, Alt-F4, right-click-close), except
## WindowsShutDown which is allowed through so the OS doesn't nag-prompt the
## operator. Removes the per-host snapshot churn from the rollup CSV by
## guaranteeing every session ends through Stop-JanetSession.
function global:Get-JanetAllowClose { return $script:JanetAllowClose }
function global:Set-JanetAllowClose { param($Value) $script:JanetAllowClose = [bool]$Value }

function Get-JanetMonthFile {
    [CmdletBinding()]
    param([switch]$Detail)
    $month = Get-Date -Format 'yyyy-MM'
    if ($Detail) { return "${month}_detail.csv" } else { return "${month}_usage.csv" }
}

function Get-JanetLocalDir {
    ## Workspace-anchored fallback under $PSScriptRoot's parent (the JANET root,
    ## peer to Logs/ and Tools/). Never %USERPROFILE% / %PROGRAMDATA% /
    ## %LOCALAPPDATA% — keeps tool data next to the launcher so portable /
    ## kiosk installs stay self-contained.
    if ($null -eq $script:JanetSession) { return $null }
    $root = Split-Path -Parent $PSScriptRoot
    $userFolder = Get-JanetUserFolderName
    $dir  = Join-Path $root ("JanetLocal\{0}\{1}" -f $script:JanetSession.Tool, $userFolder)
    if (-not (Test-Path -LiteralPath $dir)) {
        try { New-Item -Path $dir -ItemType Directory -Force -ErrorAction Stop | Out-Null } catch {}
    }
    return $dir
}

function Get-JanetLocalRollupDir {
    ## Local fallback for the fleet rollup (one row per session-snapshot or
    ## session-end). Lives at JanetLocal/_Rollup/<userfolder>/ so every tool
    ## a single operator runs writes to the same local rollup spool, mirroring
    ## the network behavior where the rollup is at the Logs/ root.
    if ($null -eq $script:JanetSession) { return $null }
    $root = Split-Path -Parent $PSScriptRoot
    $userFolder = Get-JanetUserFolderName
    $dir  = Join-Path $root ("JanetLocal\_Rollup\{0}" -f $userFolder)
    if (-not (Test-Path -LiteralPath $dir)) {
        try { New-Item -Path $dir -ItemType Directory -Force -ErrorAction Stop | Out-Null } catch {}
    }
    return $dir
}

function Initialize-JanetSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Tool,
        [Parameter(Mandatory)] [string]$Version,
        [string]$Operator = $env:USERNAME,
        [string]$ASI      = ''
    )
    ## Schema (simplified 2026-04-29): two-bucket action model. Every per-host
    ## action is either a TouchHost (just reached the box — message, scan, etc.)
    ## or a VulnPatched (changed the host's security state — patch, reboot,
    ## STIG apply, plugin remediation, package install, secure-boot enable).
    ## Rollup row carries: HostsTouched, VulnsPatched, Failures, DurationMin,
    ## ClosingNotes. ScriptsRun and Successes are deliberately gone — operators
    ## want simple totals, not categorical breakdowns.
    [PSCustomObject]@{
        StartTime    = Get-Date
        SessionId    = ([guid]::NewGuid().ToString('N').Substring(0,8))
        Operator     = $Operator
        ASI          = $ASI
        Tool         = $Tool
        Version      = $Version
        Hosts        = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        VulnsPatched = 0
        Failures     = 0
    }
}

function Get-JanetUserFolderName {
    ## Per-user subfolder name in Nemesis format: "{user} - {COMPUTER}_{user}".
    ## Mirrors Tools/ACASNemesis/Logs/<this name>/ so every JANET tool produces
    ## the same per-operator folder pattern. Sanitizes any path-illegal char.
    $u = $env:USERNAME; if ([string]::IsNullOrWhiteSpace($u)) { $u = 'Unknown' }
    $c = $env:COMPUTERNAME; if ([string]::IsNullOrWhiteSpace($c)) { $c = 'UnknownPC' }
    $name = "$u - ${c}_$u"
    return ($name -replace '[\\/:*?"<>|]', '_').Trim()
}

function Add-JanetCsvRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$NetworkPath,
        [Parameter(Mandatory)] [string]$LocalPath,
        [Parameter(Mandatory)] [string]$Line,
        [int]$MaxRetries     = 6,
        [int]$InitialDelayMs = 250
    )

    if ($script:JanetNetworkOk -eq $false -and $null -ne $script:JanetSession) {
        Write-JanetLocal -Path $LocalPath -Line $Line
        return
    }

    $delay = $InitialDelayMs
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            $dir = Split-Path -Parent $NetworkPath
            if (-not (Test-Path $dir)) {
                [void](New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop)
            }
            Add-Content -Path $NetworkPath -Value $Line -Encoding UTF8 -ErrorAction Stop
            return
        } catch {
            if ($attempt -lt $MaxRetries) {
                Start-Sleep -Milliseconds $delay
                $delay = [Math]::Min($delay * 2, 8000)
            }
        }
    }

    if ($null -ne $script:JanetSession) { $script:JanetNetworkOk = $false }
    Write-JanetLocal -Path $LocalPath -Line $Line
}

function Write-JanetLocal {
    [CmdletBinding()]
    param([string]$Path, [string]$Line)
    try {
        $dir = Split-Path -Parent $Path
        if (-not (Test-Path $dir)) {
            [void](New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop)
        }
        Add-Content -Path $Path -Value $Line -Encoding UTF8 -ErrorAction Stop
    } catch {
        Write-Host ("WARNING: JANET local fallback failed: $_") -ForegroundColor Yellow
    }
}

function Test-JanetNetwork {
    [CmdletBinding()]
    param([string]$Root = $JanetLogRoot)
    try {
        if ($Root -notmatch '^\\\\([^\\]+)') { return $false }
        $server = $Matches[1]
        $ping = Test-Connection -ComputerName $server -Count 1 -Quiet -ErrorAction SilentlyContinue
        if (-not $ping) { return $false }
        return [bool](Test-Path $Root -ErrorAction SilentlyContinue)
    } catch {
        return $false
    }
}

function Get-JanetOperatorIdentity {
    ## Returns "EDIPI - DisplayName" or just EDIPI when display-name lookup
    ## fails. Three lookup strategies, tried in order:
    ##   1. DirectorySearcher with sAMAccountName filter — works on any
    ##      AD-joined machine, doesn't depend on `whoami /fqdn` returning a
    ##      usable FQDN. This is the most reliable on AFNET.
    ##   2. [adsi]"LDAP://$(whoami /fqdn)" — SIM_Tool's classic pattern,
    ##      kept as a fallback for environments where DirectorySearcher is
    ##      blocked by policy.
    ##   3. Win32_ComputerSystem.UserName — last resort, returns
    ##      "DOMAIN\username" which we strip to bare username.
    ## Comma stripped from displayName so the value is CSV-safe in one cell.
    [CmdletBinding()] param()
    $edipi = ($env:USERNAME -replace '[\\/:*?"<>|]', '_').Trim()
    if ([string]::IsNullOrWhiteSpace($edipi)) { $edipi = 'Unknown' }

    $displayName = $null

    ## Strategy 1: DirectorySearcher (most reliable on AD-joined boxes)
    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.Filter = "(&(objectClass=user)(sAMAccountName=$env:USERNAME))"
        [void]$searcher.PropertiesToLoad.Add('displayName')
        $result = $searcher.FindOne()
        if ($result -and $result.Properties['displayname'] -and $result.Properties['displayname'].Count -gt 0) {
            $displayName = [string]$result.Properties['displayname'][0]
        }
    } catch { $displayName = $null }

    ## Strategy 2: [adsi]LDAP://whoami /fqdn (SIM_Tool's pattern)
    if ([string]::IsNullOrWhiteSpace($displayName)) {
        try {
            $fqdn = (whoami /fqdn) 2>$null
            if ($fqdn -and $fqdn.Trim()) {
                $entry = [adsi]"LDAP://$($fqdn.Trim())"
                if ($entry -and $entry.Properties -and $entry.Properties['displayName']) {
                    $vals = $entry.Properties['displayName']
                    if ($vals.Count -gt 0) { $displayName = [string]$vals[0] }
                }
            }
        } catch { $displayName = $null }
    }

    ## Strategy 3: Win32_ComputerSystem.UserName (strip DOMAIN\ prefix)
    if ([string]::IsNullOrWhiteSpace($displayName)) {
        try {
            $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
            $u = [string]$cs.UserName
            if ($u -and $u.Contains('\')) { $u = ($u -split '\\', 2)[1] }
            $displayName = $u
        } catch { $displayName = $null }
    }

    $displayName = if ($displayName) { ($displayName -replace ',', '').Trim() } else { '' }
    if ([string]::IsNullOrWhiteSpace($displayName) -or $displayName -eq $edipi) {
        return $edipi
    }
    return "$edipi - $displayName"
}

function global:Start-JanetSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Tool,
        [Parameter(Mandatory)] [string]$Version,
        [string]$Operator = (Get-JanetOperatorIdentity),
        [string]$ASI      = '',
        [switch]$SkipReplay
    )
    $script:JanetSession   = Initialize-JanetSession -Tool $Tool -Version $Version -Operator $Operator -ASI $ASI
    $script:JanetNetworkOk = Test-JanetNetwork

    if ($script:JanetNetworkOk -and -not $SkipReplay) {
        try { Invoke-JanetReplay } catch {
            Write-Host ("NOTE: JANET replay skipped: $_") -ForegroundColor Yellow
        }
    }
}

## Header strings for the two CSV families. Pinned here so every tool
## emits the exact same column order. Detail header has 10 columns; usage
## header has 10 columns. ConvertTo-JanetCsvLine uses the same comma-strip
## rules the data rows use, so the header line round-trips cleanly.
$script:JanetDetailHeader = 'Timestamp,SessionId,Operator,ASI,Tool,ToolVersion,Action,Target,Result,ItemCount,Detail'
$script:JanetUsageHeader  = 'Timestamp,SessionId,Operator,ASI,Tool,ToolVersion,RowType,HostsTouched,VulnsPatched,Failures,DurationMin,ClosingNotes'

function Add-JanetCsvHeader {
    ## Ensures both the network and local fallback CSVs are ready to receive
    ## a row in the current schema. Returns the (possibly redirected) paths
    ## the caller must use for the subsequent Add-JanetCsvRow call —
    ## $.NetworkPath and $.LocalPath. See Invoke-JanetHeaderEnsure for the
    ## four-case rotation/redirect logic.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$NetworkPath,
        [Parameter(Mandatory)] [string]$LocalPath,
        [Parameter(Mandatory)] [string]$HeaderLine
    )
    $resolvedNet   = $NetworkPath
    $resolvedLocal = $LocalPath
    try { $resolvedNet   = Invoke-JanetHeaderEnsure -Path $NetworkPath -HeaderLine $HeaderLine } catch {}
    try { $resolvedLocal = Invoke-JanetHeaderEnsure -Path $LocalPath  -HeaderLine $HeaderLine } catch {}
    return [PSCustomObject]@{ NetworkPath = $resolvedNet; LocalPath = $resolvedLocal }
}

function Invoke-JanetHeaderEnsure {
    ## Returns the path the caller should write the row to. Five cases:
    ##   1. File missing         -> mkdir, write header, return original.
    ##   2. File exists, empty   -> write header, return original. (The
    ##                              original code skipped this branch and
    ##                              left the file headerless, which produced
    ##                              2026-04_usage.csv.)
    ##   3. First line matches   -> no-op, return original.
    ##   4. First line differs,
    ##      rotation succeeds    -> rename old to <name>.legacy_<unix>.csv,
    ##                              write fresh header, return original.
    ##                              Rename retries with bounded backoff
    ##                              (200ms -> 4000ms, 6 attempts) to survive
    ##                              a peer tool's transient append lock —
    ##                              without the retry, mismatched-schema
    ##                              rows leaked into the legacy file
    ##                              (2026-05_usage.csv).
    ##   5. First line differs,
    ##      rotation fails       -> create a fresh sister CSV at
    ##                              <name>.r<unix>.csv with the current
    ##                              header, return that path. New-schema
    ##                              rows go to the sister file instead of
    ##                              corrupting the legacy file. The legacy
    ##                              file stays in place as a paper trail.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$HeaderLine
    )
    if (-not (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)) {
        $dir = Split-Path -Parent $Path
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            [void](New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop)
        }
        Add-Content -Path $Path -Value $HeaderLine -Encoding UTF8 -ErrorAction Stop
        return $Path
    }

    $first = $null
    try { $first = Get-Content -LiteralPath $Path -TotalCount 1 -ErrorAction Stop } catch {}
    $firstTrim = if ($null -ne $first) { $first.Trim() } else { '' }

    if ($firstTrim -eq '') {
        Add-Content -Path $Path -Value $HeaderLine -Encoding UTF8 -ErrorAction Stop
        return $Path
    }
    if ($firstTrim -eq $HeaderLine.Trim()) { return $Path }

    $stamp      = [int][double]((Get-Date) - (Get-Date '1970-01-01')).TotalSeconds
    $legacyName = ([IO.Path]::GetFileNameWithoutExtension($Path)) + ".legacy_$stamp.csv"
    $rotated    = $false
    $delay      = 200
    for ($attempt = 1; $attempt -le 6; $attempt++) {
        try {
            Rename-Item -LiteralPath $Path -NewName $legacyName -ErrorAction Stop
            $rotated = $true
            break
        } catch {
            if ($attempt -lt 6) {
                Start-Sleep -Milliseconds $delay
                $delay = [Math]::Min($delay * 2, 4000)
            }
        }
    }
    if ($rotated -or -not (Test-Path -LiteralPath $Path)) {
        Add-Content -Path $Path -Value $HeaderLine -Encoding UTF8 -ErrorAction Stop
        return $Path
    }

    ## Persistently locked. Redirect writes to a sister CSV so new-schema
    ## rows don't pollute the legacy file. Reuses the rotation timestamp in
    ## the suffix so concurrent writers in the same second land in the same
    ## sister file (deterministic per-second naming).
    $dir    = Split-Path -Parent $Path
    $base   = [IO.Path]::GetFileNameWithoutExtension($Path)
    $sister = Join-Path $dir ("$base.r$stamp.csv")
    Write-Host ("WARNING: JANET schema rotation failed; routing rows to sister CSV: " + $sister) -ForegroundColor Yellow
    if (-not (Test-Path -LiteralPath $sister -ErrorAction SilentlyContinue)) {
        Add-Content -Path $sister -Value $HeaderLine -Encoding UTF8 -ErrorAction Stop
    }
    return $sister
}

function Write-JanetAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('TouchHost','VulnPatched')] [string]$Action,
        [Parameter(Mandatory)] [string]$Target,
        [Parameter(Mandatory)] [ValidateSet('Success','Failure','Skipped')] [string]$Result,
        [int]$ItemCount = 0,
        [string]$Detail = ''
    )

    if ($null -eq $script:JanetSession) {
        Write-Host "WARNING: Write-JanetAction called before Start-JanetSession; ignored." -ForegroundColor Yellow
        return
    }

    ## Two-bucket action model:
    ##   TouchHost   = reached the box for any reason (message, scan, ping,
    ##                 lookup). Counts toward HostsTouched only.
    ##   VulnPatched = changed the host's security state (patch, reboot,
    ##                 STIG apply, plugin remediation, package install,
    ##                 secure-boot enable). Counts toward HostsTouched AND
    ##                 adds ItemCount to VulnsPatched.
    ## Result='Failure' increments the Failures counter regardless of bucket.
    ## Snapshot HostsTouched count BEFORE adding this host so we can detect
    ## "first time we've seen this host this session" — the trigger for
    ## emitting a real-time row to the fleet rollup CSV.
    $beforeCount = $script:JanetSession.Hosts.Count
    [void]$script:JanetSession.Hosts.Add($Target)
    $afterCount  = $script:JanetSession.Hosts.Count
    $newHost = ($afterCount -gt $beforeCount)

    if ($Result -eq 'Failure') {
        $script:JanetSession.Failures++
    }
    if ($Action -eq 'VulnPatched' -and $Result -ne 'Failure') {
        ## Failed patches don't count as "vuln patched" — only successful or
        ## skipped (where skip means already-patched, still effectively applied).
        $script:JanetSession.VulnsPatched += [int]$ItemCount
    }

    ## Per-user detail CSV — Nemesis-style folder layout:
    ##   Logs/<Tool>/<user> - <COMPUTER>_<user>/<YYYY-MM>_detail.csv
    $userFolder = Get-JanetUserFolderName
    $netDir   = Join-Path (Join-Path $JanetLogRoot $script:JanetSession.Tool) $userFolder
    $localDir = Get-JanetLocalDir
    $fileName = Get-JanetMonthFile -Detail
    $netFile   = Join-Path $netDir   $fileName
    $localFile = Join-Path $localDir $fileName

    $resolved  = Add-JanetCsvHeader -NetworkPath $netFile -LocalPath $localFile -HeaderLine $script:JanetDetailHeader
    $netFile   = $resolved.NetworkPath
    $localFile = $resolved.LocalPath

    $line = ConvertTo-JanetCsvLine @(
        (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),
        $script:JanetSession.SessionId,
        $script:JanetSession.Operator,
        $script:JanetSession.ASI,
        $script:JanetSession.Tool,
        $script:JanetSession.Version,
        $Action,
        $Target,
        $Result,
        $ItemCount,
        $Detail
    )
    Add-JanetCsvRow -NetworkPath $netFile -LocalPath $localFile -Line $line

    ## Per-host rollup snapshots removed. The form's Close Tool button is
    ## the only egress (X / Alt-F4 cancel via FormClosing guard), so every
    ## session reaches Stop-JanetSession and writes exactly one SessionEnd
    ## row to <YYYY-MM>_usage.csv. The previous design emitted a Snapshot
    ## row on every distinct-host touch (crash-resilience for force-closes
    ## that no longer happen), which made bulk runs flood the rollup CSV
    ## with hundreds of intermediate rows.
}

function Write-JanetRollupSnapshot {
    [CmdletBinding()] param([string]$ClosingNotes = '')
    if ($null -eq $script:JanetSession) { return }
    $duration    = (Get-Date) - $script:JanetSession.StartTime
    $durationMin = [Math]::Round($duration.TotalMinutes, 1)

    $line = ConvertTo-JanetCsvLine @(
        (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),
        $script:JanetSession.SessionId,
        $script:JanetSession.Operator,
        $script:JanetSession.ASI,
        $script:JanetSession.Tool,
        $script:JanetSession.Version,
        'SessionEnd',
        $script:JanetSession.Hosts.Count,
        $script:JanetSession.VulnsPatched,
        $script:JanetSession.Failures,
        $durationMin,
        $ClosingNotes
    )

    $fileName  = Get-JanetMonthFile
    $netFile   = Join-Path $JanetLogRoot              $fileName
    $localFile = Join-Path (Get-JanetLocalRollupDir)  $fileName

    $resolved  = Add-JanetCsvHeader -NetworkPath $netFile -LocalPath $localFile -HeaderLine $script:JanetUsageHeader
    $netFile   = $resolved.NetworkPath
    $localFile = $resolved.LocalPath
    Add-JanetCsvRow    -NetworkPath $netFile -LocalPath $localFile -Line $line
}

function ConvertTo-JanetCsvLine {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]]$Fields)
    $clean = $Fields | ForEach-Object {
        $s = if ($null -eq $_) { '' } else { [string]$_ }
        ($s -replace '[,\r\n]', ' ').Trim()
    }
    return ($clean -join ',')
}

function global:Stop-JanetSession {
    [CmdletBinding()]
    param(
        [string]$ClosingNotes = '',
        [switch]$ShowDialog
    )

    if ($null -eq $script:JanetSession) {
        Write-Host "WARNING: Stop-JanetSession called with no active session; ignored." -ForegroundColor Yellow
        return
    }

    if ($ShowDialog) {
        $dialogResult = Show-JanetClosingNotesForm
        if ($null -ne $dialogResult.ASI -and $dialogResult.ASI -ne '') {
            $script:JanetSession.ASI = $dialogResult.ASI
        }
        if ($null -ne $dialogResult.Notes) {
            $ClosingNotes = $dialogResult.Notes
        }
    }

    ## SessionEnd row — the only rollup row this tool writes. Schema
    ## matches $script:JanetUsageHeader (12 cols incl. SessionId + RowType).
    ## Exactly one row per session, written from Stop-JanetSession. The dashboard
    ## parser still groups by SessionId to absorb legacy v1.8.x logs that emitted
    ## intermediate Snapshot rows; new sessions never produce them.
    Write-JanetRollupSnapshot -ClosingNotes $ClosingNotes

    $script:JanetSession   = $null
    $script:JanetNetworkOk = $false
}

function Show-JanetClosingNotesForm {
    ## WPT-styled closing-notes prompt. Self-contained -- hard-codes the
    ## WPT dark palette so every tool gets identical look without depending
    ## on its own theme tables. Return shape ({ ASI; Notes }) is preserved
    ## so existing Stop-JanetSession callers keep working unchanged.
    [CmdletBinding()] param()
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.Drawing       -ErrorAction SilentlyContinue

    ## --- WPT theme palette (rgb values copy/pasted from WPT $script:WPT.UI.Theme)
    $cBg          = [System.Drawing.Color]::FromArgb(  8,   8,  12)
    $cInput       = [System.Drawing.Color]::FromArgb( 22,  22,  30)
    $cBorder      = [System.Drawing.Color]::FromArgb( 38,  34,  52)
    $cAccent1     = [System.Drawing.Color]::FromArgb(140, 100, 220)
    $cSuccess     = [System.Drawing.Color]::FromArgb( 92, 198, 120)
    $cPanelLight  = [System.Drawing.Color]::FromArgb( 30,  28,  40)
    $cTextPrimary = [System.Drawing.Color]::FromArgb(240, 240, 245)
    $cTextSec     = [System.Drawing.Color]::FromArgb(170, 168, 180)
    $cTextOnAcc   = [System.Drawing.Color]::FromArgb(255, 255, 255)

    $face       = 'Segoe UI'
    $fntBody    = New-Object System.Drawing.Font($face,  9)
    $fntPrompt  = New-Object System.Drawing.Font($face, 13, [System.Drawing.FontStyle]::Bold)
    $fntCaption = New-Object System.Drawing.Font($face,  8.25)
    $fntBtn     = New-Object System.Drawing.Font($face,  9, [System.Drawing.FontStyle]::Bold)

    $form = New-Object System.Windows.Forms.Form
    $form.Text            = 'Closing Notes'
    $form.ClientSize      = New-Object System.Drawing.Size(640, 380)
    $form.FormBorderStyle = 'FixedDialog'
    $form.StartPosition   = 'CenterScreen'
    $form.MaximizeBox     = $false
    $form.MinimizeBox     = $false
    $form.BackColor       = $cBg
    $form.ForeColor       = $cTextPrimary
    $form.Font            = $fntBody
    $form.Topmost         = $true

    ## Immersive dark title bar -- same DwmSetWindowAttribute trick WPT uses.
    ## Silent fallthrough on builds that don't support attr 19/20.
    try {
        if (-not ('JanetClosingNotes.Dwm' -as [type])) {
            Add-Type -Namespace 'JanetClosingNotes' -Name 'Dwm' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("dwmapi.dll")]
public static extern int DwmSetWindowAttribute(System.IntPtr hwnd, int attr, ref int attrValue, int attrSize);
'@ -ErrorAction Stop
        }
    } catch {}
    $form.Add_HandleCreated({
        try {
            $hwnd = $form.Handle
            if ($hwnd -ne [System.IntPtr]::Zero) {
                $on = 1
                [JanetClosingNotes.Dwm]::DwmSetWindowAttribute($hwnd, 20, [ref]$on, 4) | Out-Null
                [JanetClosingNotes.Dwm]::DwmSetWindowAttribute($hwnd, 19, [ref]$on, 4) | Out-Null
            }
        } catch {}
    }.GetNewClosure())

    ## Prompt + sub-hint (mirrors WPT's Show-WptClosingNotesDialog)
    $lblPrompt           = New-Object System.Windows.Forms.Label
    $lblPrompt.Text      = 'Anything worth noting from this session?'
    $lblPrompt.Location  = New-Object System.Drawing.Point(20, 16)
    $lblPrompt.Size      = New-Object System.Drawing.Size(600, 24)
    $lblPrompt.Font      = $fntPrompt
    $lblPrompt.ForeColor = $cAccent1
    $lblPrompt.BackColor = [System.Drawing.Color]::Transparent

    $lblHint           = New-Object System.Windows.Forms.Label
    $lblHint.Text      = 'Notes are appended to the JANET monthly usage CSV. Blank is fine.'
    $lblHint.Location  = New-Object System.Drawing.Point(20, 44)
    $lblHint.Size      = New-Object System.Drawing.Size(600, 18)
    $lblHint.Font      = $fntCaption
    $lblHint.ForeColor = $cTextSec
    $lblHint.BackColor = [System.Drawing.Color]::Transparent

    ## ASI / RFC field -- preserved from the legacy form because Stop-JanetSession
    ## reads .ASI off the result and writes it into the rollup CSV.
    $lblAsi           = New-Object System.Windows.Forms.Label
    $lblAsi.Text      = 'ASI / RFC #'
    $lblAsi.Location  = New-Object System.Drawing.Point(20, 78)
    $lblAsi.Size      = New-Object System.Drawing.Size(120, 16)
    $lblAsi.Font      = $fntCaption
    $lblAsi.ForeColor = $cTextSec
    $lblAsi.BackColor = [System.Drawing.Color]::Transparent

    $tbAsi             = New-Object System.Windows.Forms.TextBox
    $tbAsi.Location    = New-Object System.Drawing.Point(20, 96)
    $tbAsi.Size        = New-Object System.Drawing.Size(600, 24)
    $tbAsi.Font        = $fntBody
    $tbAsi.BackColor   = $cInput
    $tbAsi.ForeColor   = $cTextPrimary
    $tbAsi.BorderStyle = 'FixedSingle'

    ## Closing notes (multiline)
    $lblNotes           = New-Object System.Windows.Forms.Label
    $lblNotes.Text      = 'Closing notes'
    $lblNotes.Location  = New-Object System.Drawing.Point(20, 130)
    $lblNotes.Size      = New-Object System.Drawing.Size(120, 16)
    $lblNotes.Font      = $fntCaption
    $lblNotes.ForeColor = $cTextSec
    $lblNotes.BackColor = [System.Drawing.Color]::Transparent

    $tbNotes               = New-Object System.Windows.Forms.TextBox
    $tbNotes.Location      = New-Object System.Drawing.Point(20, 148)
    $tbNotes.Size          = New-Object System.Drawing.Size(600, 168)
    $tbNotes.Multiline     = $true
    $tbNotes.AcceptsReturn = $true
    $tbNotes.ScrollBars    = 'Vertical'
    $tbNotes.Font          = $fntBody
    $tbNotes.BackColor     = $cInput
    $tbNotes.ForeColor     = $cTextPrimary
    $tbNotes.BorderStyle   = 'FixedSingle'

    ## Buttons -- 'Submit && Exit' (Success green) + 'Skip' (PanelLight gray).
    ## Two-button rather than WPT's three-way: this dialog runs from FormClosing,
    ## so a 'Return to Tool' choice can't actually return; the form is already
    ## tearing down by the time we land here.
    $btnSubmit = New-Object System.Windows.Forms.Button
    $btnSubmit.Text         = 'Submit && Exit'
    $btnSubmit.Location     = New-Object System.Drawing.Point(380, 332)
    $btnSubmit.Size         = New-Object System.Drawing.Size(115, 32)
    $btnSubmit.FlatStyle    = 'Flat'
    $btnSubmit.FlatAppearance.BorderSize = 0
    $btnSubmit.BackColor    = $cSuccess
    $btnSubmit.ForeColor    = $cTextOnAcc
    $btnSubmit.Font         = $fntBtn
    $btnSubmit.UseVisualStyleBackColor = $false
    $btnSubmit.DialogResult = [System.Windows.Forms.DialogResult]::OK

    $btnSkip = New-Object System.Windows.Forms.Button
    $btnSkip.Text         = 'Skip'
    $btnSkip.Location     = New-Object System.Drawing.Point(505, 332)
    $btnSkip.Size         = New-Object System.Drawing.Size(115, 32)
    $btnSkip.FlatStyle    = 'Flat'
    $btnSkip.FlatAppearance.BorderSize  = 1
    $btnSkip.FlatAppearance.BorderColor = $cBorder
    $btnSkip.BackColor    = $cPanelLight
    $btnSkip.ForeColor    = $cTextPrimary
    $btnSkip.Font         = $fntBtn
    $btnSkip.UseVisualStyleBackColor = $false
    $btnSkip.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

    $form.AcceptButton = $btnSubmit
    $form.CancelButton = $btnSkip
    $form.Controls.AddRange(@($lblPrompt, $lblHint, $lblAsi, $tbAsi, $lblNotes, $tbNotes, $btnSubmit, $btnSkip))

    $result = $form.ShowDialog()
    $asi   = if ($result -eq [System.Windows.Forms.DialogResult]::OK) { $tbAsi.Text }   else { '' }
    $notes = if ($result -eq [System.Windows.Forms.DialogResult]::OK) { $tbNotes.Text } else { '' }
    $form.Dispose()

    return [PSCustomObject]@{ ASI = $asi; Notes = $notes }
}

function Invoke-JanetReplay {
    [CmdletBinding()] param()

    if ($null -eq $script:JanetSession) { return }
    $userFolder = Get-JanetUserFolderName

    ## Two local spool locations to drain:
    ##   1. JanetLocal/<Tool>/<userfolder>/<YYYY-MM>_detail.csv
    ##      → Logs/<Tool>/<userfolder>/<YYYY-MM>_detail.csv
    ##   2. JanetLocal/_Rollup/<userfolder>/<YYYY-MM>_usage.csv
    ##      → Logs/<YYYY-MM>_usage.csv
    $detailLocal = Get-JanetLocalDir
    $rollupLocal = Get-JanetLocalRollupDir

    $sources = @()
    if (Test-Path $detailLocal) {
        $detailNet = Join-Path (Join-Path $JanetLogRoot $script:JanetSession.Tool) $userFolder
        $sources += [PSCustomObject]@{ Local = $detailLocal; NetDir = $detailNet; Filter = '*_detail*.csv' }
    }
    if (Test-Path $rollupLocal) {
        $sources += [PSCustomObject]@{ Local = $rollupLocal; NetDir = $JanetLogRoot; Filter = '*_usage*.csv' }
    }

    foreach ($src in $sources) {
        $orphans = Get-ChildItem -Path $src.Local -File -ErrorAction SilentlyContinue |
            Where-Object {
                ($_.Name -like $src.Filter) -and ($_.Name -notlike '*.replayed_*') -and ($_.Name -notlike '*.legacy_*')
            }

        foreach ($orphan in $orphans) {
            if (-not (Test-Path $src.NetDir)) {
                try { [void](New-Item -ItemType Directory -Path $src.NetDir -Force -ErrorAction Stop) }
                catch { continue }
            }
            $netFile = Join-Path $src.NetDir $orphan.Name

            $replayOk = $true
            Get-Content -Path $orphan.FullName | ForEach-Object {
                ## Skip the local header row if the network file already has one —
                ## otherwise the rollup CSV ends up with a header line every time
                ## an orphan is replayed, which makes pivoting harder.
                if ($_ -like 'Timestamp,*' -and (Test-Path $netFile)) { return }
                try {
                    Add-Content -Path $netFile -Value $_ -Encoding UTF8 -ErrorAction Stop
                } catch {
                    $replayOk = $false
                }
            }

            if ($replayOk) {
                $stamp     = [int][double]((Get-Date) - (Get-Date '1970-01-01')).TotalSeconds
                $newName   = "$($orphan.Name).replayed_$stamp"
                try {
                    Rename-Item -LiteralPath $orphan.FullName -NewName $newName -ErrorAction Stop
                } catch {
                    Write-Host ("NOTE: Could not rename replayed file '$($orphan.FullName)': $_") -ForegroundColor Yellow
                }
            }
        }
    }
}

# === END JANET LOGGING BLOCK (paste to here) ===


# ----------------------------------------------------------------------------
# PAYLOAD - runs on the REMOTE machine as SYSTEM via scheduled task.
# $BIOSPassword and $ResultPath are prepended as variable assignments before
# this block is base64-encoded. Do NOT add a param() block here.
# ----------------------------------------------------------------------------
$script:Payload = @'
# $BIOSPassword and $ResultPath are injected by the launcher before this block

function New-Result {
    param($Mfr, $Current, $SetResult, $New, $Err = '')
    [PSCustomObject]@{
        Manufacturer = $Mfr
        CurrentValue = "$Current"
        SetResult    = "$SetResult"
        NewValue     = "$New"
        Error        = "$Err"
        Timestamp    = (Get-Date -Format 'o')
    }
}

function Enable-LenovoSecureBoot {
    $ns     = 'root\wmi'
    $getSB  = { Get-WmiObject -Class Lenovo_BiosSetting -Namespace $ns -EA Stop |
                    Where-Object { ($_.CurrentSetting -split ',') -contains 'SecureBoot' } }
    $current  = (& $getSB).CurrentSetting
    $setRes   = (Get-WmiObject -Class Lenovo_SetBiosSetting -Namespace $ns -EA Stop
                ).SetBiosSetting("SecureBoot,Enable,$BIOSPassword,ascii,us").return
    # Commit - without this the setting reverts on next boot. Lenovo WMI methods
    # return the STRING 'Success' on success (not 0). Capture the commit return
    # too: discarding it (the old | Out-Null) meant a refused commit was reported
    # as a clean Success while the setting silently reverted on the next reboot.
    $saveRes  = (Get-WmiObject -Class Lenovo_SaveBiosSettings -Namespace $ns -EA Stop
                ).SaveBiosSettings("$BIOSPassword,ascii,us").return
    $new = (& $getSB).CurrentSetting
    $err = ''
    if ("$setRes" -ne 'Success' -or "$saveRes" -ne 'Success') {
        $err = "Lenovo BIOS write failed (SetBiosSetting='$setRes', SaveBiosSettings='$saveRes'); check the supervisor BIOS password. Secure Boot NOT persisted."
    }
    New-Result -Mfr 'Lenovo' -Current $current -SetResult "set=$setRes; save=$saveRes" -New $new -Err $err
}

function Enable-HPSecureBoot {
    $ns          = 'root\HP\InstrumentedBIOS'
    $sbLabels    = @('Secure Boot', 'Configure Legacy Support and Secure Boot')
    $enabledVals = @('Enable', 'Legacy Support Disable and Secure Boot Enable')

    $current   = ((Get-WmiObject -Namespace $ns -Class HP_BIOSEnumeration -EA Stop |
                      Where-Object { $_.Name -in $sbLabels }) | Select-Object -First 1).CurrentValue

    $allEnum   = Get-WmiObject -Namespace $ns -Class HP_BIOSEnumeration -EA Stop
    # Select-Object -First 1: a model exposing BOTH 'Secure Boot' and 'Configure
    # Legacy Support and Secure Boot' would otherwise make $sbSetting an array,
    # and SetBIOSSetting($sbSetting.Name,...) would be passed an array Name.
    $sbSetting = $allEnum | Where-Object { $_.Name -in $sbLabels } | Select-Object -First 1
    if ($null -eq $sbSetting) {
        return New-Result -Mfr 'HP' -Current 'N/A' -SetResult 'N/A' -New 'N/A' `
            -Err 'HP: no Secure Boot setting found in HP_BIOSEnumeration; BIOS write not attempted.'
    }
    $targetVal = Compare-Object $sbSetting.PossibleValues $enabledVals `
                     -IncludeEqual -ExcludeDifferent -PassThru | Select-Object -First 1
    if ($null -eq $targetVal) {
        return New-Result -Mfr 'HP' -Current $current -SetResult 'N/A' -New 'N/A' `
            -Err ("HP: no enable-value label matched PossibleValues [" + ($sbSetting.PossibleValues -join ', ') + "]; BIOS write not attempted.")
    }

    $setRes    = (Get-WmiObject -Namespace $ns -Class HP_BIOSSettingInterface -EA Stop
                ).SetBIOSSetting($sbSetting.Name, $targetVal, "<utf-16/>$BIOSPassword").Return

    # HP quirk: HP_BIOSEnumeration.CurrentValue reflects the currently
    # BOOTED setting, not staged NVRAM changes. After SetBIOSSetting
    # returns 0 (success) the change is queued for the next boot but
    # the immediate read-back still shows the old value - this caused
    # HP rows to display "Disable -> Disable" with SetResult=Successful.
    # Dell's provider updates live, which is why Dell shows the change
    # immediately. Treat a 0 return as authoritative and report the
    # staged target with a pending-reboot marker. Any non-zero return
    # falls back to the raw read-back so real failures aren't masked.
    # HP return codes: 0=Success, 1=Not Supported, 2=Unspecified,
    # 3=Timeout, 4=Failed, 5=Invalid Param, 6=Access Denied (bad pwd).
    $postValue = ((Get-WmiObject -Namespace $ns -Class HP_BIOSEnumeration -EA Stop |
                      Where-Object { $_.Name -in $sbLabels }) | Select-Object -First 1).CurrentValue
    $err = ''
    if ($setRes -eq 0) {
        $new = "$targetVal (pending reboot)"
    } else {
        # Non-zero return is a real failure - surface it so it is NOT classified
        # as a green Success. HP codes: 1=Not Supported, 4=Failed, 5=Invalid
        # Param, 6=Access Denied (wrong BIOS password).
        $new = $postValue
        $err = "HP SetBIOSSetting returned $setRes (1=NotSupported 4=Failed 5=InvalidParam 6=AccessDenied/bad password); Secure Boot NOT staged."
    }
    New-Result -Mfr 'HP' -Current $current -SetResult $setRes -New $new -Err $err
}

function Enable-DellSecureBoot {
    $ns      = 'root/dcim/sysman/biosattributes'
    $current = (Get-CimInstance -Namespace $ns -ClassName EnumerationAttribute -EA Stop |
                    Where-Object AttributeName -eq 'SecureBoot').CurrentValue

    $enc      = [System.Text.UTF8Encoding]::new()
    $pwdBytes = $enc.GetBytes($BIOSPassword)          # avoid $pwd - it's a built-in alias

    $setRes   = ((Get-WmiObject -Namespace $ns -Class BIOSAttributeInterface -EA Stop
                ).SetAttribute(1, $pwdBytes.Length, $pwdBytes, 'SecureBoot', 'Enabled')).Status

    $new = (Get-CimInstance -Namespace $ns -ClassName EnumerationAttribute -EA Stop |
                Where-Object AttributeName -eq 'SecureBoot').CurrentValue
    # Dell SetAttribute Status: 0 = success. A non-zero (or null) Status means the
    # write was rejected - commonly a wrong/missing BIOS admin password. Surface
    # it as an error rather than letting an empty Error read as a green Success.
    $err = ''
    if ($setRes -ne 0) {
        $err = "Dell BIOS write rejected (SetAttribute Status=$setRes); a non-zero Status is usually a wrong or required BIOS admin password. Secure Boot NOT changed."
    } elseif ("$new" -eq "$current") {
        $new = "$new (no change detected)"
    }
    New-Result -Mfr 'Dell' -Current $current -SetResult $setRes -New $new -Err $err
}

# Helper - read OS-visible Secure Boot state without touching BIOS provider.
# Confirm-SecureBootUEFI returns $true/$false or throws on non-UEFI systems.
function Get-OSSecureBootState {
    try {
        $val = Confirm-SecureBootUEFI -EA Stop
        return [PSCustomObject]@{ Supported = $true; Enabled = $val }
    } catch [System.PlatformNotSupportedException] {
        return [PSCustomObject]@{ Supported = $false; Enabled = $false }
    } catch {
        return [PSCustomObject]@{ Supported = $null; Enabled = $null }
    }
}

try {
    $mfr   = (Get-CimInstance Win32_ComputerSystem -EA Stop).Manufacturer
    $osSB  = Get-OSSecureBootState

    if ($osSB.Enabled -eq $true) {
        $out = [PSCustomObject]@{
            Manufacturer = $mfr
            CurrentValue = 'Enabled'
            SetResult    = 'Skipped'
            NewValue     = 'Enabled'
            Error        = ''
            Skipped      = $true
            Timestamp    = (Get-Date -Format 'o')
        }
    }
    elseif ($osSB.Supported -eq $false) {
        $out = [PSCustomObject]@{
            Manufacturer = $mfr
            CurrentValue = 'N/A'
            SetResult    = 'N/A'
            NewValue     = 'N/A'
            Error        = 'System is not UEFI-capable. Secure Boot cannot be enabled.'
            Skipped      = $false
            Timestamp    = (Get-Date -Format 'o')
        }
    }
    # v1.3 - Treat the "unknown" branch as a hard stop. Previously
    # Supported=$null (generic Confirm-SecureBootUEFI failure: EFI
    # driver missing, insufficient rights, etc.) fell through to the
    # OEM write path and attempted a BIOS change with unverified OS
    # state. Now we bail with an informative error instead.
    elseif ($null -eq $osSB.Supported) {
        $out = [PSCustomObject]@{
            Manufacturer = $mfr
            CurrentValue = 'Unknown'
            SetResult    = 'Skipped'
            NewValue     = 'Unknown'
            Error        = 'Could not determine Secure Boot support state (Confirm-SecureBootUEFI failed). BIOS write not attempted.'
            Skipped      = $true
            Timestamp    = (Get-Date -Format 'o')
        }
    }
    else {
        # v1.5.0 BRICK-SAFETY: Confirm-SecureBootUEFI not throwing means the OS
        # booted UEFI, but a UEFI-capable box can still be on a Legacy/CSM path
        # or an MBR system disk, where committing Secure Boot (especially
        # Lenovo's persistent Save) can leave it UNBOOTABLE. Positively verify
        # UEFI firmware mode + a GPT system/boot disk and SKIP anything we cannot
        # confirm safe rather than risk a brick.
        $bootSafe = $true; $bootWhy = ''
        $fw = $env:firmware_type
        if ($fw -and $fw -ne 'UEFI') { $bootSafe = $false; $bootWhy = "firmware_type='$fw' (OS not booted in UEFI mode)" }
        if ($bootSafe) {
            try {
                $sysDisk = Get-Disk -EA Stop | Where-Object { $_.IsBoot -or $_.IsSystem } | Select-Object -First 1
                if ($null -eq $sysDisk) {
                    $bootSafe = $false; $bootWhy = 'could not identify the system/boot disk'
                } elseif ($sysDisk.PartitionStyle -ne 'GPT') {
                    $bootSafe = $false; $bootWhy = "system/boot disk is $($sysDisk.PartitionStyle), not GPT"
                }
            } catch {
                $bootSafe = $false; $bootWhy = "could not verify boot disk partition style ($($_.Exception.Message))"
            }
        }
        if (-not $bootSafe) {
            $out = [PSCustomObject]@{
                Manufacturer = $mfr
                CurrentValue = 'N/A'
                SetResult    = 'Skipped'
                NewValue     = 'N/A'
                Error        = "Brick-safety stop: $bootWhy. Enabling Secure Boot on a non-UEFI/non-GPT boot path can make the host unbootable - resolve the boot mode first. No BIOS write attempted."
                Skipped      = $true
                Timestamp    = (Get-Date -Format 'o')
            }
        }
        else {
            $out = switch -Regex ($mfr) {
                'LENOVO' { Enable-LenovoSecureBoot; break }
                'HP'     { Enable-HPSecureBoot;     break }
                'Dell'   { Enable-DellSecureBoot;   break }
                default  {
                    New-Result -Mfr $mfr -Current 'N/A' -SetResult 'N/A' -New 'N/A' `
                        -Err "Unsupported manufacturer [$mfr] - no changes made."
                }
            }
            if ($null -ne $out -and -not ($out | Get-Member -Name 'Skipped' -EA SilentlyContinue)) {
                $out | Add-Member -NotePropertyName Skipped -NotePropertyValue $false
            }
        }
    }
} catch {
    $out = [PSCustomObject]@{
        Manufacturer = 'Unknown'
        CurrentValue = 'N/A'
        SetResult    = 'N/A'
        NewValue     = 'N/A'
        Error        = $_.Exception.Message
        Skipped      = $false
        Timestamp    = (Get-Date -Format 'o')
    }
}

$out | ConvertTo-Json -Depth 5 | Out-File -FilePath $ResultPath -Encoding UTF8 -Force

# v1.5.0 SECURITY: this script file carries the BIOS password in plaintext.
# Self-delete it the instant the result is written so it does not linger on the
# target's disk (the launcher's finally + close-cleanup are backstops).
if ($PSCommandPath) { Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue }
'@

# ----------------------------------------------------------------------------
# SCRIPT-LEVEL STATE
# ----------------------------------------------------------------------------
$script:Jobs      = @{}
$script:JobTasks  = @{}        # v1.5.0: machine -> @{TaskName;Computer} for in-flight live jobs (orphan cleanup on close)
$script:Queue     = $null
$script:RowMap    = @{}
$script:Completed = 0
$script:RunIsDry  = $false     # v1.5.0: Dry-Run snapshotted at Run so a mid-run toggle can't mix live + dry targets
$script:Total     = 0

# Inherit shared credential from the J.A.N.E.T. launcher if present.
# v1.3: also verify the credential actually has an extractable password.
# Smartcard / cert-backed PSCredential objects round-trip through
# Clixml but their SecureString password is null - GetNetworkCredential
# throws at use-time, which in previous versions surfaced as "credential
# has no usable password" on every single target. Catch that at import
# time and silently fall back to the caller's token instead.
$script:InheritedCred = $null
if ($env:JANET_CRED_FILE -and (Test-Path -LiteralPath $env:JANET_CRED_FILE)) {
    try {
        $ic = Import-Clixml -Path $env:JANET_CRED_FILE -ErrorAction Stop
        if ($ic -is [System.Management.Automation.PSCredential]) {
            # Force the password to materialise - throws for smartcard creds.
            # v1.5.0: capture only a boolean, then null the NetworkCredential
            # immediately so the decrypted plaintext password is not left on the
            # heap for the lifetime of this long-running UI process. (Keep the
            # GetNetworkCredential() throw-detection - it is how smartcard/null-
            # password creds are rejected; checking SecureString.Length would miss them.)
            $probe = $null
            try { $probe = $ic.GetNetworkCredential() } catch { $probe = $null }
            $hasUsablePwd = [bool]($probe -and $probe.Password)
            $probe = $null
            if ($hasUsablePwd) {
                $script:InheritedCred = $ic
            }
        }
    } catch { <# fall back to current user #> }
}

# ----------------------------------------------------------------------------
# RESOLVE SCRIPT DIRECTORY (for logo/gif lookups)
# ----------------------------------------------------------------------------
$global:ScriptDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($global:ScriptDir)) {
    try { $global:ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path -EA Stop } catch {}
}
if ([string]::IsNullOrWhiteSpace($global:ScriptDir)) { $global:ScriptDir = (Get-Location).Path }

# ----------------------------------------------------------------------------
# THEME (Purple + Gold on Black, mirrors J.A.N.E.T. launcher)
# ----------------------------------------------------------------------------
$mkColor = { param($r,$g,$b) [System.Drawing.Color]::FromArgb($r,$g,$b) }

$theme = [pscustomobject]@{
    Background     = & $mkColor   8   8  12
    TitleBar       = & $mkColor   6   6  10
    StatusBar      = & $mkColor   7   7  11
    Surface        = & $mkColor  16  16  22
    SurfaceAlt     = & $mkColor  22  22  30
    SurfaceHover   = & $mkColor  30  28  40
    SurfaceActive  = & $mkColor  40  36  54
    Border         = & $mkColor  38  34  52
    BorderStrong   = & $mkColor  52  46  72
    Accent1        = & $mkColor 140 100 220    # #8C64DC purple
    Accent1Hover   = & $mkColor 164 128 240
    Accent1Dim     = & $mkColor  96  68 156
    Accent1Glow    = & $mkColor  28  20  48
    Accent2        = & $mkColor 218 180  82    # #DAB452 gold
    Success        = & $mkColor  92 198 120
    SuccessHover   = & $mkColor 120 220 148
    SuccessGlow    = & $mkColor  18  50  24
    Warning        = & $mkColor 230 180  70
    WarningGlow    = & $mkColor  62  48  14
    Danger         = & $mkColor 224  80  90
    DangerHover    = & $mkColor 244 110 118
    DangerGlow     = & $mkColor  64  16  18
    Info           = & $mkColor  88 180 210
    InfoGlow       = & $mkColor  12  42  68
    Skipped        = & $mkColor  70 158 158
    SkippedGlow    = & $mkColor  10  65  65
    DryRun         = & $mkColor 172 142 214
    DryRunGlow     = & $mkColor  44  34  68
    TextPrimary    = & $mkColor 240 240 245
    TextSecondary  = & $mkColor 170 168 180
    TextMuted      = & $mkColor 110 106 125
    TextFaint      = & $mkColor  60  56  74
    TextOnAccent   = & $mkColor 255 255 255    # white on purple
    GridBg         = & $mkColor  16  16  22
    GridAlt        = & $mkColor  22  22  30
    GridHeader     = & $mkColor  10  10  16
    GridSelection  = & $mkColor  28  20  48    # purple glow
    GridLine       = & $mkColor  38  34  52
    ConsoleBg      = & $mkColor   6   6  10
    ConsoleFg      = & $mkColor 164 128 240    # purple phosphor
    StripeYellow   = & $mkColor 140 100 220    # purple stripe
    StripeBlack    = & $mkColor   8   8  12
}

$mono = 'Cascadia Mono'
$body = 'Segoe UI Variable Display'

$fonts = [pscustomobject]@{
    DisplayLg  = New-Object System.Drawing.Font($mono, 18, [System.Drawing.FontStyle]::Bold)
    DisplayMd  = New-Object System.Drawing.Font($mono, 13, [System.Drawing.FontStyle]::Bold)
    DisplaySm  = New-Object System.Drawing.Font($mono, 10, [System.Drawing.FontStyle]::Bold)
    Eyebrow    = New-Object System.Drawing.Font($mono,  9, [System.Drawing.FontStyle]::Bold)
    EyebrowDim = New-Object System.Drawing.Font($mono,  8)
    Body       = New-Object System.Drawing.Font($body, 10)
    BodyStrong = New-Object System.Drawing.Font($body, 10, [System.Drawing.FontStyle]::Bold)
    Caption    = New-Object System.Drawing.Font($body,  9)
    Tiny       = New-Object System.Drawing.Font($body,  8)
    Mono       = New-Object System.Drawing.Font($mono, 10)
    MonoSm     = New-Object System.Drawing.Font($mono,  9)
    MonoTiny   = New-Object System.Drawing.Font($mono,  8)
    Icon       = New-Object System.Drawing.Font('Segoe MDL2 Assets', 14)
    IconSmall  = New-Object System.Drawing.Font('Segoe MDL2 Assets', 11)
}

$icons = [pscustomobject]@{
    Shield  = [char]0xEA18
    Target  = [char]0xE8FD
    Lock    = [char]0xE72E
    Dot     = [char]0xE915
    Refresh = [char]0xE72C
    Export  = [char]0xEDE1
    Broom   = [char]0xE74D
    Warn    = [char]0xE7BA
    Play    = [char]0xE768
}

# ----------------------------------------------------------------------------
# REFLECTION + DWM HELPERS
# ----------------------------------------------------------------------------
function Enable-DoubleBuffer {
    param([Parameter(Mandatory)]$Control)
    try {
        $prop = $Control.GetType().GetProperty('DoubleBuffered',
            [System.Reflection.BindingFlags]'Instance, NonPublic')
        if ($prop) { $prop.SetValue($Control, $true, $null) }
    } catch {}
}

function Set-DarkTitleBar {
    # Win11 immersive dark + rounded corners via DwmSetWindowAttribute
    param([Parameter(Mandatory)]$Form)
    if (-not ('Sbe.Dwm' -as [type])) {
        Add-Type -Namespace 'Sbe' -Name 'Dwm' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("dwmapi.dll")]
public static extern int DwmSetWindowAttribute(System.IntPtr hwnd, int attr, ref int attrValue, int attrSize);
'@
    }
    $hwnd = $Form.Handle
    if ($hwnd -eq [System.IntPtr]::Zero) { return }
    $enable = 1
    $null = [Sbe.Dwm]::DwmSetWindowAttribute($hwnd, 20, [ref]$enable, 4)
    $null = [Sbe.Dwm]::DwmSetWindowAttribute($hwnd, 19, [ref]$enable, 4)
    $round = 2
    $null = [Sbe.Dwm]::DwmSetWindowAttribute($hwnd, 33, [ref]$round, 4)
}

# ----------------------------------------------------------------------------
# CONTROL FACTORY
# ----------------------------------------------------------------------------
function New-SbeLabel {
    param([string]$Text = '', [int]$X = 0, [int]$Y = 0, [int]$W = 200, [int]$H = 18,
          $Font = $null, $Fg = $null)
    if (-not $Font) { $Font = $fonts.Body }
    if (-not $Fg)   { $Fg   = $theme.TextSecondary }
    $l = New-Object System.Windows.Forms.Label
    $l.Text      = $Text
    $l.Location  = New-Object System.Drawing.Point($X, $Y)
    $l.Size      = New-Object System.Drawing.Size($W, $H)
    $l.ForeColor = $Fg
    $l.BackColor = [System.Drawing.Color]::Transparent
    $l.Font      = $Font
    return $l
}

function New-SbeTextBox {
    param([int]$X = 0, [int]$Y = 0, [int]$W = 200, [int]$H = 26, [switch]$Multi, [switch]$Password)
    $t = New-Object System.Windows.Forms.TextBox
    $t.Location    = New-Object System.Drawing.Point($X, $Y)
    $t.Size        = New-Object System.Drawing.Size($W, $H)
    $t.BackColor   = $theme.SurfaceAlt
    $t.ForeColor   = $theme.TextPrimary
    $t.Font        = $fonts.Mono
    $t.BorderStyle = 'FixedSingle'
    if ($Multi)    { $t.Multiline = $true; $t.ScrollBars = 'Vertical' }
    if ($Password) { $t.UseSystemPasswordChar = $true }
    # Win11 visual-styles clobber BackColor on TextBox until the handle
    # exists. Reinforce once the HWND is real so the field doesn't flash
    # white-on-dark at startup.
    $t.Add_HandleCreated({
        $args[0].BackColor = $theme.SurfaceAlt
        $args[0].ForeColor = $theme.TextPrimary
    }.GetNewClosure())
    return $t
}

function New-SbeButton {
    param([Parameter(Mandatory)][string]$Text, [int]$X = 0, [int]$Y = 0, [int]$W = 140, [int]$H = 32,
          $Bg = $null, $Fg = $null, $Font = $null)
    if (-not $Bg)   { $Bg   = $theme.Accent1 }
    if (-not $Fg) {
        $lum = (0.299 * $Bg.R + 0.587 * $Bg.G + 0.114 * $Bg.B) / 255.0
        if ($lum -gt 0.55) { $Fg = $theme.TextOnAccent } else { $Fg = $theme.TextPrimary }
    }
    if (-not $Font) { $Font = $fonts.DisplaySm }
    $b = New-Object System.Windows.Forms.Button
    $b.Text      = $Text.ToUpperInvariant()
    $b.Location  = New-Object System.Drawing.Point($X, $Y)
    $b.Size      = New-Object System.Drawing.Size($W, $H)
    $b.FlatStyle = 'Flat'
    $b.FlatAppearance.BorderSize = 0
    $b.BackColor = $Bg
    $b.ForeColor = $Fg
    $b.Font      = $Font
    $b.Cursor    = [System.Windows.Forms.Cursors]::Hand
    $b.UseVisualStyleBackColor = $false
    $hover = [System.Drawing.Color]::FromArgb([Math]::Min(255,$Bg.R+28), [Math]::Min(255,$Bg.G+28), [Math]::Min(255,$Bg.B+28))
    $down  = [System.Drawing.Color]::FromArgb([Math]::Max(0,$Bg.R-20), [Math]::Max(0,$Bg.G-20), [Math]::Max(0,$Bg.B-20))
    $b.FlatAppearance.MouseOverBackColor = $hover
    $b.FlatAppearance.MouseDownBackColor = $down
    return $b
}

function New-SbeGhostButton {
    param([Parameter(Mandatory)][string]$Text, [int]$X = 0, [int]$Y = 0, [int]$W = 140, [int]$H = 32, $Fg = $null)
    if (-not $Fg) { $Fg = $theme.TextSecondary }
    $b = New-Object System.Windows.Forms.Button
    $b.Text      = $Text.ToUpperInvariant()
    $b.Location  = New-Object System.Drawing.Point($X, $Y)
    $b.Size      = New-Object System.Drawing.Size($W, $H)
    $b.FlatStyle = 'Flat'
    $b.FlatAppearance.BorderSize  = 1
    $b.FlatAppearance.BorderColor = $theme.BorderStrong
    $b.BackColor = $theme.Background
    $b.ForeColor = $Fg
    $b.Font      = $fonts.DisplaySm
    $b.Cursor    = [System.Windows.Forms.Cursors]::Hand
    $b.UseVisualStyleBackColor = $false
    $b.FlatAppearance.MouseOverBackColor = $theme.SurfaceHover
    $b.FlatAppearance.MouseDownBackColor = $theme.SurfaceActive
    return $b
}

function New-SbeStripeButton {
    # Primary CTA: purple + diagonal stripe at bottom 4px
    param([Parameter(Mandatory)][string]$Text, [int]$X = 0, [int]$Y = 0, [int]$W = 240, [int]$H = 44)
    $b = New-SbeButton -Text $Text -X $X -Y $Y -W $W -H $H -Bg $theme.Accent1 -Fg $theme.TextOnAccent -Font $fonts.DisplayMd
    $b.FlatAppearance.MouseOverBackColor = $theme.Accent1Hover
    $stripeH = 4
    $stripe1 = $theme.StripeYellow
    $stripe2 = $theme.StripeBlack
    $b.Add_Paint({
        param($sender, $e)
        $hatch = New-Object System.Drawing.Drawing2D.HatchBrush('WideDownwardDiagonal', $stripe2, $stripe1)
        try {
            $rect = New-Object System.Drawing.Rectangle(0, ($sender.Height - $stripeH), $sender.Width, $stripeH)
            $e.Graphics.FillRectangle($hatch, $rect)
        } finally { $hatch.Dispose() }
    }.GetNewClosure())
    return $b
}

function New-SbeCheckBox {
    param([string]$Text, [int]$X = 0, [int]$Y = 0, [int]$W = 250, [int]$H = 24, $Fg = $null, [bool]$Checked = $false)
    if (-not $Fg) { $Fg = $theme.TextPrimary }
    $c = New-Object System.Windows.Forms.CheckBox
    $c.Text       = $Text
    $c.Location   = New-Object System.Drawing.Point($X, $Y)
    $c.Size       = New-Object System.Drawing.Size($W, $H)
    $c.ForeColor  = $Fg
    $c.BackColor  = $theme.Surface
    $c.Font       = $fonts.Body
    $c.Checked    = $Checked
    $c.Cursor     = [System.Windows.Forms.Cursors]::Hand
    $c.Appearance = 'Button'
    $c.FlatStyle  = 'Flat'
    $c.FlatAppearance.BorderSize         = 0
    $c.FlatAppearance.CheckedBackColor   = $theme.Surface
    $c.FlatAppearance.MouseOverBackColor = $theme.SurfaceHover
    $c.FlatAppearance.MouseDownBackColor = $theme.SurfaceActive
    $c.TextAlign = 'MiddleLeft'
    $c.Padding   = New-Object System.Windows.Forms.Padding(26, 0, 0, 0)
    $c.AutoSize  = $false

    $borderOff = $theme.BorderStrong
    $borderOn  = $theme.Accent1
    $fillOn    = $theme.Accent1
    $checkFg   = $theme.TextOnAccent
    $c.Add_Paint({
        param($sender, $e)
        $g = $e.Graphics
        $g.SmoothingMode = 'AntiAlias'
        $box = 14; $bx = 4; $by = [int](($sender.Height - $box) / 2)
        if ($sender.Checked) {
            $fill = New-Object System.Drawing.SolidBrush($fillOn)
            try { $g.FillRectangle($fill, $bx, $by, $box, $box) } finally { $fill.Dispose() }
            $pen = New-Object System.Drawing.Pen($borderOn, 1)
            try { $g.DrawRectangle($pen, $bx, $by, $box, $box) } finally { $pen.Dispose() }
            $cp = New-Object System.Drawing.Pen($checkFg, 2)
            try {
                $p1 = New-Object System.Drawing.Point(($bx + 3),  ($by + 7))
                $p2 = New-Object System.Drawing.Point(($bx + 6),  ($by + 10))
                $p3 = New-Object System.Drawing.Point(($bx + 11), ($by + 4))
                $g.DrawLines($cp, @($p1, $p2, $p3))
            } finally { $cp.Dispose() }
        } else {
            $pen = New-Object System.Drawing.Pen($borderOff, 1)
            try { $g.DrawRectangle($pen, $bx, $by, $box, $box) } finally { $pen.Dispose() }
        }
    }.GetNewClosure())
    $c.Add_CheckedChanged({ $args[0].Invalidate() })
    return $c
}

function New-SbeNumericUpDown {
    param([int]$X = 0, [int]$Y = 0, [int]$W = 70, [int]$H = 26, [int]$Min = 1, [int]$Max = 10, [int]$Value = 5)
    $n = New-Object System.Windows.Forms.NumericUpDown
    $n.Location    = New-Object System.Drawing.Point($X, $Y)
    $n.Size        = New-Object System.Drawing.Size($W, $H)
    $n.Minimum     = $Min
    $n.Maximum     = $Max
    $n.Value       = $Value
    $n.BackColor   = $theme.SurfaceAlt
    $n.ForeColor   = $theme.TextPrimary
    $n.Font        = $fonts.Mono
    $n.BorderStyle = 'FixedSingle'
    # NumericUpDown is a composite: Controls[0] is the up/down buttons,
    # Controls[1] is the inner TextBox. Setting BackColor on the outer
    # control does NOT cascade to the child edit region, so the "5"
    # renders black-on-white until we push the color down manually.
    $n.Add_HandleCreated({
        $self = $args[0]
        $self.BackColor = $theme.SurfaceAlt
        $self.ForeColor = $theme.TextPrimary
        foreach ($child in $self.Controls) {
            $child.BackColor = $theme.SurfaceAlt
            $child.ForeColor = $theme.TextPrimary
        }
    }.GetNewClosure())
    return $n
}

function New-SbeCard {
    # Surface panel with 4 L-shaped corner brackets.
    param([string]$Header, [int]$X = 0, [int]$Y = 0, [int]$W = 400, [int]$H = 200,
          $Fg = $null, [int]$Padding = 18, [int]$BracketLen = 18, [int]$BracketThick = 2)
    if (-not $Fg) { $Fg = $theme.Accent1 }
    $card = New-Object System.Windows.Forms.Panel
    $card.Location  = New-Object System.Drawing.Point($X, $Y)
    $card.Size      = New-Object System.Drawing.Size($W, $H)
    $card.BackColor = $theme.Surface
    $card.Padding   = New-Object System.Windows.Forms.Padding($Padding)
    Enable-DoubleBuffer -Control $card
    # Force full repaint on resize so brackets never ghost at old edge
    $card.Add_SizeChanged({ $this.Invalidate() })

    $bracketColor = $Fg
    $underColor   = [System.Drawing.Color]::FromArgb(90, $Fg.R, $Fg.G, $Fg.B)
    $hasHdr       = -not [string]::IsNullOrWhiteSpace($Header)
    $card.Add_Paint({
        param($sender, $e)
        $g = $e.Graphics
        $g.SmoothingMode = 'HighQuality'
        $pen = New-Object System.Drawing.Pen($bracketColor, $BracketThick)
        try {
            $w = $sender.Width  - 1
            $h = $sender.Height - 1
            $L = $BracketLen
            $g.DrawLine($pen, 0, 0, $L, 0); $g.DrawLine($pen, 0, 0, 0, $L)
            $g.DrawLine($pen, ($w - $L), 0, $w, 0); $g.DrawLine($pen, $w, 0, $w, $L)
            $g.DrawLine($pen, 0, ($h - $L), 0, $h); $g.DrawLine($pen, 0, $h, $L, $h)
            $g.DrawLine($pen, ($w - $L), $h, $w, $h); $g.DrawLine($pen, $w, ($h - $L), $w, $h)
        } finally { $pen.Dispose() }
        if ($hasHdr) {
            $dotPen = New-Object System.Drawing.Pen($underColor, 1)
            $dotPen.DashStyle = 'Dot'
            try { $g.DrawLine($dotPen, $Padding, 38, ($sender.Width - $Padding), 38) }
            finally { $dotPen.Dispose() }
        }
    }.GetNewClosure())

    if ($hasHdr) {
        $hdr = New-Object System.Windows.Forms.Label
        $hdr.Text      = "/ $($Header.ToUpperInvariant())"
        $hdr.Location  = New-Object System.Drawing.Point($Padding, 12)
        $hdr.Size      = New-Object System.Drawing.Size(($W - $Padding * 2), 22)
        $hdr.ForeColor = $Fg
        $hdr.BackColor = [System.Drawing.Color]::Transparent
        $hdr.Font      = $fonts.Eyebrow
        $card.Controls.Add($hdr)
    }
    return $card
}

function New-SbeBadge {
    param([Parameter(Mandatory)][string]$Text, [int]$X = 0, [int]$Y = 0, [int]$W = 110, [int]$H = 20,
          $Fg = $null, $Bg = $null)
    if (-not $Fg) { $Fg = $theme.Accent1 }
    if (-not $Bg) { $Bg = [System.Drawing.Color]::FromArgb(40, $Fg.R, $Fg.G, $Fg.B) }
    $l = New-Object System.Windows.Forms.Label
    $l.Text      = $Text.ToUpperInvariant()
    $l.Location  = New-Object System.Drawing.Point($X, $Y)
    $l.Size      = New-Object System.Drawing.Size($W, $H)
    $l.ForeColor = $Fg
    $l.BackColor = $Bg
    $l.Font      = $fonts.MonoTiny
    $l.TextAlign = 'MiddleCenter'
    return $l
}

function New-SbePulseIndicator {
    param([int]$X = 0, [int]$Y = 0, [int]$Size = 10,
          [ValidateSet('Active','Idle','Alert')][string]$State = 'Idle')
    $p = New-Object System.Windows.Forms.Panel
    $p.Location  = New-Object System.Drawing.Point($X, $Y)
    $p.Size      = New-Object System.Drawing.Size($Size, $Size)
    $p.BackColor = [System.Drawing.Color]::Transparent
    $color1 = switch ($State) {
        'Active' { $theme.Success }
        'Alert'  { $theme.Danger }
        default  { $theme.TextMuted }
    }
    $color2 = [System.Drawing.Color]::FromArgb(40, $color1.R, $color1.G, $color1.B)
    $p.Tag = @{ Phase = 0; State = $State; C1 = $color1; C2 = $color2 }
    $p.Add_Paint({
        param($sender, $e)
        $t = $sender.Tag
        $c = if ($t.Phase -eq 0 -or $t.State -eq 'Idle') { $t.C1 } else { $t.C2 }
        $e.Graphics.SmoothingMode = 'AntiAlias'
        $brush = New-Object System.Drawing.SolidBrush($c)
        try { $e.Graphics.FillEllipse($brush, 0, 0, ($sender.Width - 1), ($sender.Height - 1)) }
        finally { $brush.Dispose() }
    }.GetNewClosure())
    if ($State -ne 'Idle') {
        $interval = if ($State -eq 'Alert') { 300 } else { 700 }
        $timer = New-Object System.Windows.Forms.Timer
        $timer.Interval = $interval
        $timer.Add_Tick({ $p.Tag.Phase = 1 - $p.Tag.Phase; $p.Invalidate() }.GetNewClosure())
        $timer.Start()
        $p.Tag.Timer = $timer
    }
    return $p
}

function Set-SbePulseState {
    param([Parameter(Mandatory)]$Indicator,
          [ValidateSet('Active','Idle','Alert')][string]$State)
    $t = $Indicator.Tag
    $t.State = $State
    $t.C1 = switch ($State) {
        'Active' { $theme.Success }
        'Alert'  { $theme.Danger }
        default  { $theme.TextMuted }
    }
    $t.C2 = [System.Drawing.Color]::FromArgb(40, $t.C1.R, $t.C1.G, $t.C1.B)
    if ($t.Timer) { $t.Timer.Stop(); $t.Timer.Dispose(); $t.Timer = $null }
    if ($State -ne 'Idle') {
        $interval = if ($State -eq 'Alert') { 300 } else { 700 }
        $timer = New-Object System.Windows.Forms.Timer
        $timer.Interval = $interval
        $timer.Add_Tick({ $Indicator.Tag.Phase = 1 - $Indicator.Tag.Phase; $Indicator.Invalidate() }.GetNewClosure())
        $timer.Start()
        $t.Timer = $timer
    }
    $Indicator.Invalidate()
}

# ----------------------------------------------------------------------------
# CHANGELOG - shown via the top-bar Changelog button
# Keep this in a plain here-string (ASCII only) so the PS 5.1 parser
# is happy regardless of the script's on-disk encoding. The viewer
# highlights "v<x.y>" headers in amber and bullet lines in secondary
# text so the version boundaries are easy to scan.
# ----------------------------------------------------------------------------
$script:Changelog = @'
v1.3 - April 2026 - HP After-column fix + hardening (validated)
  - HP: HP_BIOSEnumeration.CurrentValue reflects the currently BOOTED
    setting, not staged NVRAM. Enable-HPSecureBoot now treats a 0
    return from SetBIOSSetting as authoritative and reports the
    staged target with a "(pending reboot)" suffix. Non-zero returns
    still fall back to the raw read so real failures stay visible.
  - Security: BIOS password is single-quote-escaped before being
    baked into the encoded payload. A password with a single quote
    previously broke the generated source and could inject code
    that ran as SYSTEM on every target.
  - Dry-run uses DCOM via New-CimSession (matches the live transport)
    instead of the default WSMan. Green dry-runs are now actually
    predictive of live reachability.
  - Scheduled-task cleanup is wrapped in a finally block so the
    Unregister is guaranteed even if Start-ScheduledTask throws or
    the 90s result-polling window expires.
  - OS precheck: Confirm-SecureBootUEFI returning an unknown state
    is now a hard stop instead of silently falling through to a
    BIOS write.
  - Credential inherit now rejects smartcard-derived PSCredential
    objects whose password SecureString is null.
  - Form-close path disposes the polling timer and both pulse-
    indicator timers, and removes only this tool's jobs.
  - MinimumSize raised to 1200 x 680 so the right-column cards no
    longer clip at the floor width.
  - Validated: Dell (live "Disabled -> Enabled"), HP ("Disable ->
    Enable (pending reboot)" with a post-reboot rerun correctly
    classifying the host as Skipped), Lenovo (SaveBiosSettings
    persisted through reboot). BIOS password literal "password".

v1.2 - April 2026 - GUI restyle to the J.A.N.E.T. Purple + Gold theme
  - Cascadia Mono display + Segoe UI Variable Display body
  - Corner-bracket cards with /HEADER eyebrows and dotted underlines
  - Caution-stripe primary CTA, flat ghost secondary buttons
  - Live pulse indicator, dark immersive title bar (DwmSetWindow-
    Attribute), custom-paint progress track
  - Status strip footer (user / targets / creds)
  - All payload logic, scheduled-task plumbing, credential handling,
    and polling timer behaviour preserved byte-for-byte from v1.1

v1.1 - Inherited J.A.N.E.T. launcher credential via $env:JANET_CRED_FILE
  - Child Start-Job runspaces use Import-Clixml on the DPAPI-sealed
    credential file and New-CimSession -Credential with it, instead
    of relying on the caller's token.

v1.0 - Initial release
  - CIM/DCOM scheduled-task deployment of Secure Boot enable payload
  - Dell / HP / Lenovo OEM branches
  - OS-level pre-check via Confirm-SecureBootUEFI skips BIOS write
    when already enabled; hard fail on non-UEFI systems
  - Result JSON polled back via \\host\C$\Windows\Temp
'@

function Show-SbeChangelog {
    <#
    .SYNOPSIS
        Modal dialog showing $script:Changelog in the JANET theme.
    .DESCRIPTION
        RichTextBox-based viewer so we can syntax-highlight version
        headers (amber) and bullets (dim text). Sized to fit on a
        1080p display without maximising, resizable, dark immersive
        title bar to match the main form.
    #>
    param([Parameter(Mandatory)]$Owner)

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text            = "Secure Boot Enabler - Changelog"
    $dlg.Size            = New-Object System.Drawing.Size(760, 560)
    $dlg.MinimumSize     = New-Object System.Drawing.Size(520, 360)
    $dlg.StartPosition   = 'CenterParent'
    $dlg.BackColor       = $theme.Background
    $dlg.ForeColor       = $theme.TextPrimary
    $dlg.Font            = $fonts.Body
    $dlg.FormBorderStyle = 'Sizable'
    $dlg.ShowInTaskbar   = $false
    Enable-DoubleBuffer -Control $dlg
    $dlg.Add_HandleCreated({ try { Set-DarkTitleBar -Form $dlg } catch {} })

    # Eyebrow heading
    $hdr = New-SbeLabel -Text "J.A.N.E.T // SECURE BOOT   CHANGELOG" `
        -X 18 -Y 14 -W 700 -H 22 -Font $fonts.Eyebrow -Fg $theme.Accent1
    $hdr.Anchor = 'Top,Left,Right'
    $dlg.Controls.Add($hdr)

    # Dotted underline - same visual language as card headers
    $underline = New-Object System.Windows.Forms.Panel
    $underline.Location  = New-Object System.Drawing.Point(18, 38)
    $underline.Size      = New-Object System.Drawing.Size(720, 1)
    $underline.Anchor    = 'Top,Left,Right'
    $underline.BackColor = [System.Drawing.Color]::FromArgb(90, $theme.Accent1.R, $theme.Accent1.G, $theme.Accent1.B)
    $dlg.Controls.Add($underline)

    # Scrollable text body
    $rtb = New-Object System.Windows.Forms.RichTextBox
    $rtb.Location    = New-Object System.Drawing.Point(18, 50)
    $rtb.Size        = New-Object System.Drawing.Size(720, 430)
    $rtb.Anchor      = 'Top,Left,Right,Bottom'
    $rtb.ReadOnly    = $true
    $rtb.BorderStyle = 'None'
    $rtb.BackColor   = $theme.Surface
    $rtb.ForeColor   = $theme.TextSecondary
    $rtb.Font        = $fonts.MonoSm
    $rtb.WordWrap    = $true
    $rtb.ScrollBars  = 'Vertical'
    $rtb.Text        = $script:Changelog
    $dlg.Controls.Add($rtb)

    # Syntax colour pass - version headers amber, bullets dim, rest neutral.
    # Walk the Lines collection manually instead of regex-on-RTF so the
    # offsets are stable and multi-byte-safe.
    $offset = 0
    foreach ($line in $rtb.Lines) {
        $len = $line.Length
        if ($line -match '^v\d+\.\d+') {
            $rtb.Select($offset, $len)
            $rtb.SelectionColor = $theme.Accent1
            $rtb.SelectionFont  = $fonts.DisplaySm
        } elseif ($line -match '^\s*-\s') {
            $rtb.Select($offset, $len)
            $rtb.SelectionColor = $theme.TextSecondary
        } else {
            $rtb.Select($offset, $len)
            $rtb.SelectionColor = $theme.TextMuted
        }
        $offset += $len + 1   # +1 for the newline the Lines collection strips
    }
    $rtb.Select(0, 0)

    # Close button (ghost style, bottom-right, anchored)
    $btnClose = New-SbeGhostButton -Text "Close" -X 0 -Y 0 -W 120 -H 32 -Fg $theme.Accent1
    $btnClose.Anchor = 'Bottom,Right'
    $dlg.Controls.Add($btnClose)
    $btnClose.Add_Click({ $dlg.Close() })
    # Esc / Enter also dismiss
    $dlg.KeyPreview = $true
    $dlg.Add_KeyDown({
        if ($_.KeyCode -eq 'Escape' -or $_.KeyCode -eq 'Enter') { $dlg.Close() }
    })

    $dlg.Add_Layout({
        $w = $dlg.ClientSize.Width
        $h = $dlg.ClientSize.Height
        $btnClose.Location = New-Object System.Drawing.Point(($w - 140), ($h - 46))
    }.GetNewClosure())

    [void]$dlg.ShowDialog($Owner)
    $dlg.Dispose()
}

# ----------------------------------------------------------------------------
# MAIN FORM
# ----------------------------------------------------------------------------
$form = New-Object System.Windows.Forms.Form
if ($script:InheritedCred) {
    $form.Text = "J.A.N.E.T // Secure Boot  -  running as $($script:InheritedCred.UserName)"
} else {
    $form.Text = "J.A.N.E.T // Secure Boot"
}
$form.Size          = New-Object System.Drawing.Size(1200, 760)
# MinimumSize is floor-gated by the right-column cards:
# cardOpts/cardGrid live at X=344 W=822 -> right edge 1166. Body
# panel content area is form.ClientSize.Width - 14px horizontal
# padding, so a form width of 1200 gives ~1184 body width, with
# ~18px margin before the card bracket hits the form edge.
$form.MinimumSize   = New-Object System.Drawing.Size(1200, 680)
$form.StartPosition = 'CenterScreen'
$form.BackColor     = $theme.Background
$form.ForeColor     = $theme.TextPrimary
$form.Font          = $fonts.Body
Enable-DoubleBuffer -Control $form
$form.Add_HandleCreated({ try { Set-DarkTitleBar -Form $form } catch {} })

# ----------------------------------------------------------------------------
# TOP BAR
# ----------------------------------------------------------------------------
$topBar = New-Object System.Windows.Forms.Panel
$topBar.Dock      = 'Top'
$topBar.Height    = 72
$topBar.BackColor = $theme.TitleBar
Enable-DoubleBuffer -Control $topBar

$topUnderline = New-Object System.Windows.Forms.Panel
$topUnderline.Dock      = 'Bottom'
$topUnderline.Height    = 1
$topUnderline.BackColor = $theme.Accent1
$topBar.Controls.Add($topUnderline)

$titleLabel = New-SbeLabel -Text "J.A.N.E.T // Secure Boot" -X 78 -Y 12 -W 700 -H 26 -Font $fonts.DisplayMd -Fg $theme.TextPrimary
$topBar.Controls.Add($titleLabel)

$eyebrow = New-SbeLabel -Text "Remote BIOS config for Dell, HP, Lenovo" -X 80 -Y 38 -W 700 -H 16 -Font $fonts.EyebrowDim -Fg $theme.TextMuted
$topBar.Controls.Add($eyebrow)

# Live pulse - green = idle/ready, amber alert when a run errors
$pulseTitle = New-SbePulseIndicator -X 0 -Y 31 -Size 10 -State 'Active'
$pulseTitle.Anchor = 'Top,Right'
$topBar.Controls.Add($pulseTitle)

# Changelog button - opens the in-tool changelog viewer. Anchored to
# the top bar's right edge, placed left of the pulse with 12px spacing.
$btnChangelog = New-SbeGhostButton -Text "Changelog" -X 0 -Y 22 -W 110 -H 28 -Fg $theme.TextSecondary
$btnChangelog.Anchor = 'Top,Right'
$topBar.Controls.Add($btnChangelog)
$btnChangelog.Add_Click({ Show-SbeChangelog -Owner $form })

# Close Tool — top-right of the top bar (matches WPT pattern). Single
# sanctioned form egress: sets the X-block allow flag, then closes;
# FormClosing guard cancels every other origin.
$btnCloseTool = New-SbeGhostButton -Text 'Close Tool' -X 0 -Y 22 -W 110 -H 28 -Fg $theme.Danger
$btnCloseTool.Anchor = 'Top,Right'
$topBar.Controls.Add($btnCloseTool)
$btnCloseTool.Add_Click({
    Set-JanetAllowClose $true
    $form.Close()
}.GetNewClosure())

$topBar.Add_Layout({
    $w = $topBar.ClientSize.Width
    $pulseTitle.Location    = New-Object System.Drawing.Point(($w - 22), 31)
    $btnChangelog.Location  = New-Object System.Drawing.Point(($w - 22 - 12 - 110), 22)
    $btnCloseTool.Location  = New-Object System.Drawing.Point(($w - 22 - 12 - 110 - 12 - 110), 22)
}.GetNewClosure())

$form.Controls.Add($topBar)

# ----------------------------------------------------------------------------
# STATUS STRIP (bottom)
# ----------------------------------------------------------------------------
$statusStrip = New-Object System.Windows.Forms.Panel
$statusStrip.Dock      = 'Bottom'
$statusStrip.Height    = 50
$statusStrip.BackColor = $theme.StatusBar
$statusStrip.Padding   = New-Object System.Windows.Forms.Padding(12, 0, 12, 0)
Enable-DoubleBuffer -Control $statusStrip

$statusUnder = New-Object System.Windows.Forms.Panel
$statusUnder.Dock = 'Top'; $statusUnder.Height = 1; $statusUnder.BackColor = $theme.Border
$statusStrip.Controls.Add($statusUnder)

## Close Tool button moved to the top bar (top-right, mirroring WPT).
## Status strip now shows session metadata only.

$lblStatUser = New-SbeLabel -Text "user: $($env:USERNAME)" -X 12 -Y 17 -W 260 -H 16 -Font $fonts.MonoSm -Fg $theme.TextMuted
$script:lblStatTargets = New-SbeLabel -Text "targets: 0" -X 280 -Y 17 -W 120 -H 16 -Font $fonts.MonoSm -Fg $theme.TextMuted
$credText = if ($script:InheritedCred) { "creds: $($script:InheritedCred.UserName) (inherited)" } else { "creds: caller token" }
$lblStatCred = New-SbeLabel -Text $credText -X 408 -Y 17 -W 700 -H 16 -Font $fonts.MonoSm -Fg $theme.TextFaint
$lblStatCred.Anchor = 'Top,Left,Right'
$statusStrip.Controls.AddRange(@($lblStatUser, $script:lblStatTargets, $lblStatCred))

$form.Controls.Add($statusStrip)

# ----------------------------------------------------------------------------
# BODY
# ----------------------------------------------------------------------------
$bodyPanel = New-Object System.Windows.Forms.Panel
$bodyPanel.Dock       = 'Fill'
$bodyPanel.BackColor  = $theme.Background
$bodyPanel.Padding    = New-Object System.Windows.Forms.Padding(14, 12, 14, 8)
# AutoScroll on a Fill-docked panel interacts poorly with Bottom-anchored
# children (the child's "distance from bottom" is computed against the
# scrollable area, not the visible area, and results in a dead band
# below the last card). Layout is tuned so content fits without scroll.
$bodyPanel.AutoScroll = $false
Enable-DoubleBuffer -Control $bodyPanel
$form.Controls.Add($bodyPanel)
$bodyPanel.BringToFront()

# --- Targets card (left column) --------------------------------------------
$cardTargets = New-SbeCard -Header "Targets" -X 14 -Y 12 -W 320 -H 576 -Fg $theme.Info
$cardTargets.Anchor = 'Top,Left,Bottom'
$bodyPanel.Controls.Add($cardTargets)

$lblTgtCap = New-SbeLabel -Text "One hostname per line - up to 50" -X 18 -Y 44 -W 280 -H 16 -Font $fonts.Caption -Fg $theme.TextMuted
$cardTargets.Controls.Add($lblTgtCap)

$txtMachines = New-SbeTextBox -X 18 -Y 64 -W 284 -H 470 -Multi
$txtMachines.Anchor = 'Top,Left,Right,Bottom'
$cardTargets.Controls.Add($txtMachines)

$lblCount = New-SbeLabel -Text "0 / 50" -X 18 -Y 542 -W 120 -H 18 -Font $fonts.MonoSm -Fg $theme.TextMuted
$lblCount.Anchor = 'Bottom,Left'
$cardTargets.Controls.Add($lblCount)

$btnClearTgts = New-SbeGhostButton -Text "Clear" -X 222 -Y 538 -W 80 -H 26 -Fg $theme.Danger
$btnClearTgts.Anchor = 'Bottom,Right'
$cardTargets.Controls.Add($btnClearTgts)

$txtMachines.Add_TextChanged({
    $n = ($txtMachines.Lines | Where-Object { $_.Trim() -ne '' }).Count
    if ($n -gt 50) {
        $lblCount.ForeColor = $theme.Danger
    } else {
        $lblCount.ForeColor = $theme.TextMuted
    }
    $lblCount.Text = "$n / 50"
    $script:lblStatTargets.Text = "targets: $n"
})

$btnClearTgts.Add_Click({
    $txtMachines.Clear()
})

# --- Settings card (top right) ---------------------------------------------
$cardOpts = New-SbeCard -Header "Settings" -X 344 -Y 12 -W 822 -H 178 -Fg $theme.Accent1
$cardOpts.Anchor = 'Top,Left,Right'
$bodyPanel.Controls.Add($cardOpts)

# Row 1: BIOS password
$lblPassEye = New-SbeLabel -Text "BIOS password" -X 18 -Y 50 -W 140 -H 18 -Font $fonts.Eyebrow -Fg $theme.TextSecondary
$cardOpts.Controls.Add($lblPassEye)

$txtPass = New-SbeTextBox -X 160 -Y 48 -W 300 -H 26 -Password
$cardOpts.Controls.Add($txtPass)

$chkShow = New-SbeCheckBox -Text "Show" -X 470 -Y 46 -W 90 -H 28
$cardOpts.Controls.Add($chkShow)
$chkShow.Add_CheckedChanged({ $txtPass.UseSystemPasswordChar = -not $chkShow.Checked })

$lblPassNote = New-SbeLabel -Text "Leave blank if none is set" -X 570 -Y 52 -W 240 -H 18 -Font $fonts.Caption -Fg $theme.TextFaint
$lblPassNote.Anchor = 'Top,Left,Right'
$cardOpts.Controls.Add($lblPassNote)

# Row 2: parallel jobs
$lblJobsEye = New-SbeLabel -Text "Parallel jobs" -X 18 -Y 90 -W 140 -H 18 -Font $fonts.Eyebrow -Fg $theme.TextSecondary
$cardOpts.Controls.Add($lblJobsEye)

$numJobs = New-SbeNumericUpDown -X 160 -Y 88 -W 70 -H 26 -Min 1 -Max 10 -Value 5
$cardOpts.Controls.Add($numJobs)

$lblJobsNote = New-SbeLabel -Text "Concurrent machines (1 - 10)" -X 240 -Y 92 -W 300 -H 18 -Font $fonts.Caption -Fg $theme.TextFaint
$cardOpts.Controls.Add($lblJobsNote)

# Row 3: dry run toggle
$chkDry = New-SbeCheckBox -Text "Dry Run - connectivity + manufacturer detection only. No BIOS write." -X 18 -Y 130 -W 780 -H 28 -Fg $theme.Warning
$cardOpts.Controls.Add($chkDry)

# --- Action bar card (between Settings and Results) -------------------------
# Wrapped in a card so the corner brackets continue visually between the
# Settings card above and the Results card below. A bare Panel made the
# primary CTA look like it was floating with no right terminator.
$pnlActions = New-SbeCard -X 344 -Y 202 -W 822 -H 60 -Fg $theme.Accent1
$pnlActions.Anchor = 'Top,Left,Right'
$bodyPanel.Controls.Add($pnlActions)

# Left side: run-state pulse + status line
$pulseMission = New-SbePulseIndicator -X 18 -Y 25 -Size 10 -State 'Idle'
$pnlActions.Controls.Add($pulseMission)

$lblStatus = New-SbeLabel -Text "Ready" -X 36 -Y 21 -W 260 -H 20 -Font $fonts.BodyStrong -Fg $theme.TextSecondary
$pnlActions.Controls.Add($lblStatus)

# Right cluster: Export / Clear / Run (primary).
# Positioned by the Layout handler so they stay anchored to the card's
# right edge as it resizes, with a consistent 18px inner margin.
$btnExport = New-SbeGhostButton -Text "Export CSV" -X 0 -Y 14 -W 130 -H 32
$btnExport.Anchor = 'Top,Right'
$pnlActions.Controls.Add($btnExport)

$btnClear = New-SbeGhostButton -Text "Clear" -X 0 -Y 14 -W 90 -H 32 -Fg $theme.Danger
$btnClear.Anchor = 'Top,Right'
$pnlActions.Controls.Add($btnClear)

$btnRun = New-SbeStripeButton -Text "Enable Secure Boot" -X 0 -Y 8 -W 240 -H 44
$btnRun.Anchor = 'Top,Right'
$pnlActions.Controls.Add($btnRun)

$pnlActions.Add_Layout({
    $margin = 18
    $w = $pnlActions.ClientSize.Width
    $btnRun.Location    = New-Object System.Drawing.Point(($w - $margin - 240), 8)
    $btnClear.Location  = New-Object System.Drawing.Point(($w - $margin - 240 - 10 - 90), 14)
    $btnExport.Location = New-Object System.Drawing.Point(($w - $margin - 240 - 10 - 90 - 8 - 130), 14)
}.GetNewClosure())

# --- Results card -----------------------------------------------------------
$cardGrid = New-SbeCard -Header "Results" -X 344 -Y 268 -W 822 -H 320 -Fg $theme.Accent1
$cardGrid.Anchor = 'Top,Left,Right,Bottom'
$bodyPanel.Controls.Add($cardGrid)

$dgv = New-Object System.Windows.Forms.DataGridView
$dgv.Location        = New-Object System.Drawing.Point(18, 50)
$dgv.Size            = New-Object System.Drawing.Size(786, 230)
$dgv.Anchor          = 'Top,Left,Right,Bottom'
$dgv.BackgroundColor = $theme.GridBg
$dgv.GridColor       = $theme.GridLine
$dgv.BorderStyle     = 'None'
$dgv.CellBorderStyle = 'SingleHorizontal'
$dgv.EnableHeadersVisualStyles = $false
$dgv.ColumnHeadersDefaultCellStyle.BackColor = $theme.GridHeader
$dgv.ColumnHeadersDefaultCellStyle.ForeColor = $theme.Accent1
$dgv.ColumnHeadersDefaultCellStyle.Font      = $fonts.Eyebrow
$dgv.ColumnHeadersHeight          = 30
$dgv.ColumnHeadersHeightSizeMode  = 'DisableResizing'
$dgv.RowTemplate.Height           = 24
$dgv.DefaultCellStyle.BackColor          = $theme.GridBg
$dgv.DefaultCellStyle.ForeColor          = $theme.TextPrimary
$dgv.DefaultCellStyle.SelectionBackColor = $theme.GridSelection
$dgv.DefaultCellStyle.SelectionForeColor = $theme.TextPrimary
$dgv.DefaultCellStyle.Font               = $fonts.Mono
$dgv.AlternatingRowsDefaultCellStyle.BackColor = $theme.GridAlt
$dgv.RowHeadersVisible     = $false
$dgv.AllowUserToAddRows    = $false
$dgv.AllowUserToDeleteRows = $false
$dgv.AllowUserToResizeRows = $false
$dgv.ReadOnly              = $true
$dgv.SelectionMode         = 'FullRowSelect'
$dgv.MultiSelect           = $false
$dgv.AutoSizeColumnsMode   = 'Fill'
# Header row was wrapping "SET RESULT" onto two lines. Lock to single-line.
$dgv.ColumnHeadersDefaultCellStyle.WrapMode = 'False'
$dgv.DefaultCellStyle.WrapMode              = 'False'
Enable-DoubleBuffer -Control $dgv

@(
    [pscustomobject]@{ H='Computer';      N='Computer';     W=110 }
    [pscustomobject]@{ H='Status';        N='Status';       W=70  }
    [pscustomobject]@{ H='Manufacturer';  N='Manufacturer'; W=95  }
    [pscustomobject]@{ H='Before';        N='Before';       W=85  }
    [pscustomobject]@{ H='After';         N='After';        W=85  }
    [pscustomobject]@{ H='Result';        N='SetResult';    W=75  }
    [pscustomobject]@{ H='Error / Notes'; N='Error';        W=265 }
) | ForEach-Object {
    $c = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $c.HeaderText = $_.H.ToUpperInvariant()
    $c.Name       = $_.N
    $c.FillWeight = $_.W
    [void]$dgv.Columns.Add($c)
}

# Row colour coding by status (mapped onto theme)
$dgv.Add_RowPrePaint({
    param($s, $e)
    $status = $dgv.Rows[$e.RowIndex].Cells['Status'].Value
    $bg = switch ($status) {
        'Success' { $theme.SuccessGlow }
        'Skipped' { $theme.SkippedGlow }
        'Error'   { $theme.DangerGlow }
        'Timeout' { $theme.WarningGlow }
        'Running' { $theme.InfoGlow }
        'DryRun'  { $theme.DryRunGlow }
        default   { $theme.GridBg }
    }
    $fg = switch ($status) {
        'Success' { $theme.Success }
        'Skipped' { $theme.Skipped }
        'Error'   { $theme.Danger }
        'Timeout' { $theme.Warning }
        'Running' { $theme.Info }
        'DryRun'  { $theme.DryRun }
        default   { $theme.TextPrimary }
    }
    $dgv.Rows[$e.RowIndex].DefaultCellStyle.BackColor = $bg
    $dgv.Rows[$e.RowIndex].DefaultCellStyle.ForeColor = $fg
})
$cardGrid.Controls.Add($dgv)

# Custom flat progress track below the grid. Native ProgressBar can't be
# themed well (renders as a bright white strip when empty), so we paint
# our own 3px track that stays invisible at Value=0 / Maximum=0.
$progress = New-Object System.Windows.Forms.Panel
$progress.Location  = New-Object System.Drawing.Point(18, 290)
$progress.Size      = New-Object System.Drawing.Size(786, 3)
$progress.Anchor    = 'Left,Right,Bottom'
$progress.BackColor = $theme.Border
$progress | Add-Member -NotePropertyName Value   -NotePropertyValue 0 -Force
$progress | Add-Member -NotePropertyName Maximum -NotePropertyValue 0 -Force
Enable-DoubleBuffer -Control $progress
$progress.Add_Paint({
    param($sender, $e)
    $max = [int]$sender.Maximum
    if ($max -le 0) { return }
    $frac = [double]([int]$sender.Value) / [double]$max
    if ($frac -lt 0) { $frac = 0 } elseif ($frac -gt 1) { $frac = 1 }
    $w    = [int]([Math]::Round($sender.Width * $frac))
    if ($w -le 0) { return }
    $brush = New-Object System.Drawing.SolidBrush($theme.Accent1)
    try { $e.Graphics.FillRectangle($brush, 0, 0, $w, $sender.Height) }
    finally { $brush.Dispose() }
}.GetNewClosure())
# Invalidate whenever Value changes - the Add_Paint handler re-reads it.
$progress | Add-Member -MemberType ScriptMethod -Name Refresh2 -Value { $this.Invalidate() } -Force
$cardGrid.Controls.Add($progress)

# ----------------------------------------------------------------------------
# CLICK HANDLERS for secondary buttons
# ----------------------------------------------------------------------------
$btnClear.Add_Click({
    $dgv.Rows.Clear()
    $progress.Value = 0
    $progress.Maximum = 0
    $progress.Invalidate()
    $lblStatus.Text = "Ready"
    $lblStatus.ForeColor = $theme.TextSecondary
    Set-SbePulseState -Indicator $pulseMission -State 'Idle'
})

$btnExport.Add_Click({
    if ($dgv.Rows.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('No results to export.', 'Export', 'OK', 'Information') | Out-Null
        return
    }
    $sfd          = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter   = 'CSV Files (*.csv)|*.csv'
    $sfd.FileName = "SecureBoot_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($sfd.ShowDialog() -eq 'OK') {
        $rows = foreach ($row in $dgv.Rows) {
            [PSCustomObject]@{
                Computer     = $row.Cells['Computer'].Value
                Status       = $row.Cells['Status'].Value
                Manufacturer = $row.Cells['Manufacturer'].Value
                Before       = $row.Cells['Before'].Value
                After        = $row.Cells['After'].Value
                SetResult    = $row.Cells['SetResult'].Value
                Error        = $row.Cells['Error'].Value
            }
        }
        $rows | Export-Csv -Path $sfd.FileName -NoTypeInformation -Encoding UTF8
        [System.Windows.Forms.MessageBox]::Show("Exported to:`n$($sfd.FileName)", 'Export Complete', 'OK', 'Information') | Out-Null
    }
})

# ----------------------------------------------------------------------------
# POLL TIMER - feeds queue, harvests finished jobs, updates grid
# ----------------------------------------------------------------------------
$script:PollTimer          = New-Object System.Windows.Forms.Timer
$script:PollTimer.Interval = 800

$script:PollTimer.Add_Tick({
    $maxJobs = [int]$numJobs.Value

    # Feed queue -> active jobs
    while ($script:Jobs.Count -lt $maxJobs -and $script:Queue.Count -gt 0) {
        $machine = $script:Queue.Dequeue()
        $rowIdx  = $script:RowMap[$machine]
        $dgv.Rows[$rowIdx].Cells['Status'].Value = 'Running'

        $isDry   = $script:RunIsDry   # v1.5.0: snapshotted at Run so a mid-run Dry-Run toggle can't mix live + dry targets in one batch
        # v1.4 SECURITY: marshal the BIOS password as SecureString across the
        # Start-Job boundary. PS jobs DPAPI-protect SecureString arguments
        # (per-user, per-session) so the plaintext doesn't sit in the job's
        # parameter table or get serialized in cleartext over the IPC channel.
        # The plaintext STILL has to be reconstituted inside the job to bake
        # into the base64-encoded scheduled-task payload (no way around that —
        # BIOS APIs require it), but the unprotect window is scoped to a few
        # lines and the BSTR is zeroed in finally. See the unprotect block
        # below for the threat-model commentary on what this does and
        # doesn't mitigate.
        $biosPwdSec = New-Object System.Security.SecureString
        foreach ($_c in $txtPass.Text.ToCharArray()) { $biosPwdSec.AppendChar($_c) }
        $biosPwdSec.MakeReadOnly()
        $payload = $script:Payload
        $jobCred = $script:InheritedCred
        # v1.5.0: generate the task name in the PARENT (was Get-Random inside the
        # job) so the close handler can clean up an orphaned task if the job is
        # force-killed mid-poll before its finally runs.
        $taskName = "SBE_$(Get-Random -Maximum 999999)"

        if ($isDry) {
            # v1.3 - Dry-run now uses the SAME DCOM-based CIM session
            # mechanism as the live run instead of Get-CimInstance's
            # default WSMan transport. On networks where WinRM is
            # disabled but DCOM+RPC is allowed (typical AFNET stance)
            # the old dry-run would fail on hosts that would have
            # succeeded in live mode. Now a green dry-run is actually
            # predictive of live reachability.
            $job = Start-Job -ScriptBlock {
                param($comp, $cred)
                $cim = $null
                try {
                    $cimOpt = New-CimSessionOption -Protocol Dcom
                    $cim = if ($cred) {
                        New-CimSession -ComputerName $comp -SessionOption $cimOpt `
                            -Credential $cred -OperationTimeoutSec 20 -EA Stop
                    } else {
                        New-CimSession -ComputerName $comp -SessionOption $cimOpt `
                            -OperationTimeoutSec 20 -EA Stop
                    }
                    $mfr = (Get-CimInstance -CimSession $cim `
                                -ClassName Win32_ComputerSystem -EA Stop).Manufacturer
                    [PSCustomObject]@{
                        Computer     = $comp
                        Status       = 'DryRun'
                        Manufacturer = $mfr
                        Before       = 'N/A (Dry Run)'
                        After        = 'N/A (Dry Run)'
                        SetResult    = 'N/A (Dry Run)'
                        Error        = ''
                    }
                } catch {
                    # Dry-run failure == predicted live failure. Mark
                    # the row red so it's visually distinct from a
                    # successful preflight.
                    [PSCustomObject]@{
                        Computer     = $comp
                        Status       = 'Error'
                        Manufacturer = '?'
                        Before       = 'N/A (Dry Run)'
                        After        = 'N/A (Dry Run)'
                        SetResult    = 'N/A (Dry Run)'
                        Error        = "DCOM/CIM unreachable: $($_.Exception.Message)"
                    }
                } finally {
                    if ($cim) { Remove-CimSession $cim -EA SilentlyContinue }
                }
            } -ArgumentList $machine, $jobCred

        } else {
            $job = Start-Job -ScriptBlock {
                param([System.Security.SecureString]$biosPasswordSec, $comp, $payloadScript, $cred, $taskName)

                $resultFile = "SecureBoot_${comp}.json"
                $remotePath = "C:\Windows\Temp\$resultFile"
                # C$ is an admin share; the $ literal must be escaped
                # inside the double-quoted expansion so PS doesn't try
                # to interpolate "$\Windows".
                $uncPath    = "\\$comp\C`$\Windows\Temp\$resultFile"
                # v1.5.0: the payload is delivered as an admin-ACL'd .ps1 on the
                # target (not in the task command line). $localScriptPath is what
                # the task runs with -File; $scriptUnc is how we write/clean it.
                $scriptFile      = "$taskName.ps1"
                $localScriptPath = "C:\Windows\Temp\$scriptFile"
                $scriptUnc       = "\\$comp\C`$\Windows\Temp\$scriptFile"

                Remove-Item -LiteralPath $uncPath -Force -EA SilentlyContinue

                # v1.3/v1.5.0 SECURITY: escape single quotes in BOTH values baked
                # into single-quoted PS literals - the password AND $remotePath
                # (which embeds the operator-supplied hostname). The v1.3 fix only
                # escaped the password, leaving the hostname as a SYSTEM code-
                # injection vector; hostnames are also allow-list validated at the
                # Run button, so this is defense-in-depth. Single-quoted PS strings
                # are literal (no backtick / $ interpretation) so doubling ' suffices.
                #
                # v1.4/v1.5.0 SECURITY: unprotect the SecureString only here and
                # ZeroFreeBSTR immediately. v1.5.0 no longer ships the password in
                # the scheduled-task command line (-EncodedCommand is reversible
                # Base64 and the task XML is readable by any local user). The payload
                # is written to a SYSTEM+Administrators-only file on the target and
                # run with -File; the payload self-deletes it and we remove it in
                # finally. Plaintext still reaches the target (BIOS WMI needs it at
                # the call site) but is no longer recoverable from the task by a
                # standard user, and the on-disk window is one run.
                $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($biosPasswordSec)
                try {
                    $plain      = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
                    $escPwd     = $plain -replace "'", "''"
                    $escPath    = $remotePath -replace "'", "''"
                    $fullScript = "`$BIOSPassword = '$escPwd'`n" +
                                  "`$ResultPath   = '$escPath'`n" +
                                  $payloadScript
                } finally {
                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                    $plain      = $null
                    $escPwd     = $null
                }

                $cim       = $null
                $taskOwned = $false        # true once Register succeeds
                $result    = $null
                $earlyErr  = $null
                $fileSeen  = $false        # result file ever observed on the share
                $lastParseErr = $null
                try {
                    # v1.5.0 SECURITY: drop the password-bearing payload to a file
                    # on the target, lock it to SYSTEM + Administrators (well-known
                    # SIDs, best-effort), and run it with -File - NOT in the task
                    # command line. $fullScript (plaintext) is released right after.
                    Set-Content -LiteralPath $scriptUnc -Value $fullScript -Encoding UTF8 -Force -EA Stop
                    $fullScript = $null
                    & icacls.exe "$scriptUnc" /inheritance:r /grant:r "*S-1-5-18:(M)" "*S-1-5-32-544:(M)" 2>$null | Out-Null

                    $cimOpt = New-CimSessionOption -Protocol Dcom
                    $cim = if ($cred) {
                        New-CimSession -ComputerName $comp -SessionOption $cimOpt `
                            -Credential $cred -OperationTimeoutSec 30 -EA Stop
                    } else {
                        New-CimSession -ComputerName $comp -SessionOption $cimOpt `
                            -OperationTimeoutSec 30 -EA Stop
                    }

                    $action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
                                   -Argument "-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$localScriptPath`""
                    $princ   = New-ScheduledTaskPrincipal -UserId 'SYSTEM' `
                                   -RunLevel Highest -LogonType ServiceAccount
                    $stSet   = New-ScheduledTaskSettingsSet `
                                   -ExecutionTimeLimit (New-TimeSpan -Minutes 5) `
                                   -MultipleInstances IgnoreNew

                    Register-ScheduledTask -TaskName $taskName -Action $action `
                        -Principal $princ -Settings $stSet -CimSession $cim -Force -EA Stop | Out-Null
                    $taskOwned = $true
                    Start-ScheduledTask -TaskName $taskName -CimSession $cim -EA Stop

                    # Poll for the result JSON. 90s deadline, 4s interval. Read
                    # whenever the file exists (not gated on task state) and accept
                    # only a parse that has the expected fields, so a half-written
                    # file is retried rather than accepted as a fieldless object.
                    $deadline = (Get-Date).AddSeconds(90)
                    while ((Get-Date) -lt $deadline) {
                        Start-Sleep -Seconds 4
                        if (Test-Path -LiteralPath $uncPath) {
                            $fileSeen = $true
                            try {
                                $parsed = Get-Content -LiteralPath $uncPath -Raw | ConvertFrom-Json
                                if ($parsed -and ($parsed.PSObject.Properties.Name -contains 'SetResult')) { $result = $parsed; break }
                            } catch { $lastParseErr = $_.Exception.Message }
                        }
                    }
                    # One final read after the deadline: the payload may have
                    # finished writing in the last interval. Without this a host
                    # that succeeded ~now is reported Timeout and the operator
                    # re-runs an enable that actually worked.
                    if ($null -eq $result -and (Test-Path -LiteralPath $uncPath)) {
                        $fileSeen = $true
                        try {
                            $parsed = Get-Content -LiteralPath $uncPath -Raw | ConvertFrom-Json
                            if ($parsed -and ($parsed.PSObject.Properties.Name -contains 'SetResult')) { $result = $parsed }
                        } catch { $lastParseErr = $_.Exception.Message }
                    }
                } catch {
                    $m = $_.Exception.Message
                    if ($m -match 'Access is denied|0x80070005|Access Denied') {
                        $earlyErr = "Access denied to $comp (check the credential / that the account is a local admin on the target): $m"
                    } else {
                        $earlyErr = $m
                    }
                } finally {
                    # v1.3/v1.5.0 - cleanup MUST run even if Register/Start threw:
                    # unregister the task, drop the CIM session, and remove BOTH the
                    # result file and the password-bearing script file from the target.
                    $fullScript = $null
                    if ($taskOwned -and $cim) {
                        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false `
                            -CimSession $cim -EA SilentlyContinue
                    }
                    if ($cim) { Remove-CimSession $cim -EA SilentlyContinue }
                    Remove-Item -LiteralPath $uncPath   -Force -EA SilentlyContinue
                    Remove-Item -LiteralPath $scriptUnc -Force -EA SilentlyContinue
                }

                if ($earlyErr) {
                    return [PSCustomObject]@{
                        Computer=$comp; Status='Error'; Manufacturer='?'
                        Before='?'; After='?'; SetResult='?'
                        Error=$earlyErr
                    }
                }
                if ($null -eq $result) {
                    # Distinguish corrupt-but-present, C$ not accessible, and a
                    # genuine no-show. The finally above already removed the result
                    # file, so rely on $fileSeen captured during polling + a dir probe.
                    if ($fileSeen) {
                        $msg = if ($lastParseErr) { "Result file was present but unreadable/corrupt: $lastParseErr" }
                               else { 'Result file present but missing expected fields (payload may have crashed mid-write).' }
                        return [PSCustomObject]@{ Computer=$comp; Status='Error'; Manufacturer='?'; Before='?'; After='?'; SetResult='?'; Error=$msg }
                    }
                    if (-not (Test-Path -LiteralPath "\\$comp\C`$\Windows\Temp" -EA SilentlyContinue)) {
                        return [PSCustomObject]@{ Computer=$comp; Status='Error'; Manufacturer='?'; Before='?'; After='?'; SetResult='?'; Error="C`$ admin share not accessible on $comp (permission denied or unreachable); the task may have run but the result could not be read." }
                    }
                    return [PSCustomObject]@{ Computer=$comp; Status='Timeout'; Manufacturer='?'; Before='?'; After='?'; SetResult='?'; Error='Payload ran but produced no result within 90 s.' }
                }
                $resolvedStatus = if     ($result.Skipped -eq $true) { 'Skipped' }
                                  elseif ($result.Error)              { 'Error'   }
                                  else                                { 'Success' }
                return [PSCustomObject]@{
                    Computer     = $comp
                    Status       = $resolvedStatus
                    Manufacturer = $result.Manufacturer
                    Before       = $result.CurrentValue
                    After        = $result.NewValue
                    SetResult    = $result.SetResult
                    Error        = $result.Error
                }
            } -ArgumentList $biosPwdSec, $machine, $payload, $jobCred, $taskName
        }

        $script:Jobs[$machine] = $job
        # v1.5.0: track the live task so the close handler can clean up an
        # orphaned SYSTEM task if the job is force-killed mid-poll (its finally
        # would not run). Dry-run jobs register no task, so skip them.
        if (-not $isDry) { $script:JobTasks[$machine] = @{ TaskName = $taskName; Computer = $machine } }
    }

    # Harvest finished jobs
    $done = @($script:Jobs.GetEnumerator() |
              Where-Object { $_.Value.State -in @('Completed', 'Failed') })

    foreach ($entry in $done) {
        $machine = $entry.Key
        $job     = $entry.Value
        $rowIdx  = $script:RowMap[$machine]

        try {
            $r = Receive-Job -Job $job -EA Stop
            if ($null -eq $r) { throw 'Job returned no data.' }
            if (-not $r.Computer) { $r | Add-Member -NotePropertyName Computer -NotePropertyValue $machine -Force }
            $dgv.Rows[$rowIdx].Cells['Computer'].Value     = $r.Computer
            $dgv.Rows[$rowIdx].Cells['Status'].Value       = $r.Status
            $dgv.Rows[$rowIdx].Cells['Manufacturer'].Value = $r.Manufacturer
            $dgv.Rows[$rowIdx].Cells['Before'].Value       = $r.Before
            $dgv.Rows[$rowIdx].Cells['After'].Value        = $r.After
            $dgv.Rows[$rowIdx].Cells['SetResult'].Value    = $r.SetResult
            $dgv.Rows[$rowIdx].Cells['Error'].Value        = $r.Error
        } catch {
            $dgv.Rows[$rowIdx].Cells['Status'].Value = 'Error'
            $dgv.Rows[$rowIdx].Cells['Error'].Value  = $_.Exception.Message
        }

        Remove-Job -Job $job -Force -EA SilentlyContinue
        $script:Jobs.Remove($machine)
        $script:JobTasks.Remove($machine)   # v1.5.0: task finished - no orphan cleanup needed
        $script:Completed++
        $progress.Value = [Math]::Min($script:Completed, $progress.Maximum)
        $progress.Invalidate()

        ## JANET centralized logging (v1.4.1: two-bucket model). Enabling Secure
        ## Boot is a security-state change -> VulnPatched (counts toward
        ## VulnsPatched). ItemCount=1 per successful enable.
        $finalStatus = $dgv.Rows[$rowIdx].Cells['Status'].Value
        # v1.5.0: do NOT log dry-run previews to JANET. A 'DryRun' row is neither
        # 'Success' nor 'Skipped', so the old mapping logged it as VulnPatched/
        # Failure - inflating session Failures and writing a phantom remediation
        # row for a connectivity-only preflight that changed nothing.
        if ($null -ne $script:JanetSession -and $finalStatus -ne 'DryRun') {
            $janetResult = if ($finalStatus -eq 'Success') { 'Success' } elseif ($finalStatus -eq 'Skipped') { 'Skipped' } else { 'Failure' }
            $itemCount   = if ($janetResult -eq 'Success') { 1 } else { 0 }
            $detail = $dgv.Rows[$rowIdx].Cells['Error'].Value
            try { Write-JanetAction -Action 'VulnPatched' -Target $machine -Result $janetResult -ItemCount $itemCount -Detail $detail } catch {}
        }
    }

    # Status readout
    $lblStatus.Text = "Running: $($script:Jobs.Count)   Queued: $($script:Queue.Count)   Done: $($script:Completed) / $($script:Total)"
    $lblStatus.ForeColor = $theme.Accent1
    $dgv.Refresh()

    # All complete?
    if ($script:Total -gt 0 -and
        $script:Completed -ge $script:Total -and
        $script:Queue.Count -eq 0 -and
        $script:Jobs.Count  -eq 0) {

        $script:PollTimer.Stop()
        $btnRun.Enabled = $true
        $btnRun.Text    = "Enable Secure Boot".ToUpperInvariant()
        # v1.5.0: re-enable the inputs that were locked for the duration of the run.
        $chkDry.Enabled = $true; $numJobs.Enabled = $true; $txtPass.Enabled = $true

        $successCount = ($dgv.Rows | Where-Object { $_.Cells['Status'].Value -eq 'Success' }).Count
        $skippedCount = ($dgv.Rows | Where-Object { $_.Cells['Status'].Value -eq 'Skipped' }).Count
        $dryCount     = ($dgv.Rows | Where-Object { $_.Cells['Status'].Value -eq 'DryRun'  }).Count
        $errCount     = $script:Total - $successCount - $skippedCount - $dryCount

        if ($errCount -eq 0) {
            Set-SbePulseState -Indicator $pulseMission -State 'Active'
            $lblStatus.ForeColor = $theme.Success
        } else {
            Set-SbePulseState -Indicator $pulseMission -State 'Alert'
            $lblStatus.ForeColor = $theme.Danger
        }
        $lblStatus.Text = "Complete - $successCount success, $skippedCount skipped, $errCount error/timeout"

        [System.Windows.Forms.MessageBox]::Show(
            "Run complete.`n`n" +
            "  Success          : $successCount`n" +
            "  Already Enabled  : $skippedCount`n" +
            $(if ($dryCount) { "  Dry Run          : $dryCount`n" } else { '' }) +
            "  Error / Timeout  : $errCount`n`n" +
            "Total machines: $($script:Total)",
            'Secure Boot Enabler',
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
    }
})

# ----------------------------------------------------------------------------
# RUN BUTTON
# ----------------------------------------------------------------------------
$btnRun.Add_Click({
    $machines = @(
        $txtMachines.Lines |
        Where-Object { $_.Trim() -ne '' } |
        ForEach-Object { $_.Trim().ToUpper() } |
        Select-Object -Unique
    )

    if ($machines.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            'Enter at least one machine name.', 'Input Required', 'OK', 'Warning') | Out-Null
        return
    }
    if ($machines.Count -gt 50) {
        $extra  = $machines.Count - 50
        $suffix = if ($extra -eq 1) { 'y' } else { 'ies' }
        [System.Windows.Forms.MessageBox]::Show(
            "Maximum 50 machines per run.`nPlease remove $extra extra entr$suffix.",
            'Limit Exceeded', 'OK', 'Warning') | Out-Null
        return
    }
    # v1.5.0 SECURITY: hostnames are baked into the SYSTEM payload (result path)
    # and into UNC/file paths. A name with a quote or shell metacharacter could
    # break out of the payload literal (code execution as SYSTEM) or mis-resolve
    # a path. Valid NetBIOS/DNS names never contain those, so reject anything
    # outside a strict allow-list up front rather than escaping at every sink.
    $badNames = @($machines | Where-Object { $_ -notmatch '^[A-Za-z0-9._-]+$' })
    if ($badNames.Count -gt 0) {
        [System.Windows.Forms.MessageBox]::Show(
            ("These target names are not valid hostnames and were not run:`n`n{0}`n`nUse only letters, digits, dot, hyphen, and underscore." -f ($badNames -join "`n")),
            'Invalid Target Name', 'OK', 'Warning') | Out-Null
        return
    }
    # v1.5.0: a comma, quote, or backtick in the BIOS password corrupts the
    # comma-delimited Lenovo/HP WMI argument string (silent auth failure / wrong
    # setting). Reject up front - these are never valid in a firmware password here.
    if (-not $chkDry.Checked) {
        $pwForbidden = @(',', "'", '"', '`')
        if ($pwForbidden | Where-Object { $txtPass.Text.Contains($_) }) {
            [System.Windows.Forms.MessageBox]::Show(
                "The BIOS password contains a character that corrupts the firmware WMI call (comma, single/double quote, or backtick). Remove it and retry.",
                'Unsupported Password Character', 'OK', 'Warning') | Out-Null
            return
        }
    }
    if (-not $chkDry.Checked -and $txtPass.Text -eq '') {
        $ans = [System.Windows.Forms.MessageBox]::Show(
            "No BIOS password entered.`n`nContinue anyway?`n(Works only if the BIOS has no password set.)",
            'No Password', 'YesNo', 'Warning')
        if ($ans -ne 'Yes') { return }
    }

    # Reset state
    $script:RunIsDry  = $chkDry.Checked   # v1.5.0: snapshot the mode for the whole run
    $dgv.Rows.Clear()
    $script:Jobs      = @{}
    $script:JobTasks  = @{}
    $script:Queue     = [System.Collections.Generic.Queue[string]]::new()
    $script:RowMap    = @{}
    $script:Completed = 0
    $script:Total     = $machines.Count
    $progress.Maximum = $script:Total
    $progress.Value   = 0

    foreach ($m in $machines) {
        $idx = $dgv.Rows.Add($m, 'Pending', '-', '-', '-', '-', '')
        $script:RowMap[$m] = $idx
        $script:Queue.Enqueue($m)
    }

    $btnRun.Enabled = $false
    $btnRun.Text    = "Running...".ToUpperInvariant()
    # v1.5.0: lock the inputs that must not change mid-run (re-enabled on completion).
    $chkDry.Enabled = $false; $numJobs.Enabled = $false; $txtPass.Enabled = $false
    $lblStatus.Text = "Starting $($machines.Count) target$(if ($machines.Count -eq 1) {''} else {'s'})..."
    $lblStatus.ForeColor = $theme.Accent1
    $progress.Invalidate()
    Set-SbePulseState -Indicator $pulseMission -State 'Active'
    $script:PollTimer.Start()
})

# ----------------------------------------------------------------------------
# CLEAN UP ON CLOSE
# v1.3 - Dispose every Timer we own and remove only the jobs WE
# started (tracked via $script:Jobs), not anything that happens to
# match a default "^Job" name. If this tool is launched from a
# JANET launcher session that already has unrelated background jobs,
# the old `Get-Job -match '^Job'` filter would have torched them too.
# ----------------------------------------------------------------------------
Set-JanetAllowClose $false
$form.Add_FormClosing({
    param($sender, $e)

    ## X-block: only the Close Tool button is allowed to actually close
    ## the form. Any other origin (X chrome button, Alt-F4, right-click
    ## title-bar Close) hits the FormClosing pipeline and gets cancelled
    ## here. WindowsShutDown is excepted — let the OS shut down cleanly
    ## instead of forcing the operator through the nag-prompt loop.
    if (-not (Get-JanetAllowClose) -and $e.CloseReason -ne [System.Windows.Forms.CloseReason]::WindowsShutDown) {
        $e.Cancel = $true
        return
    }

    # Stop + dispose the polling timer
    if ($script:PollTimer) {
        try { $script:PollTimer.Stop() } catch {}
        try { $script:PollTimer.Dispose() } catch {}
    }
    # Stop + dispose the pulse-indicator timers (tucked inside $p.Tag.Timer)
    foreach ($p in @($pulseTitle, $pulseMission)) {
        if ($p -and $p.Tag -and $p.Tag.Timer) {
            try { $p.Tag.Timer.Stop() } catch {}
            try { $p.Tag.Timer.Dispose() } catch {}
        }
    }
    # Kill only the jobs WE started. Snapshot the hashtable values
    # because Stop-Job / Remove-Job can mutate state mid-iteration.
    $ourJobs = @($script:Jobs.Values)
    foreach ($j in $ourJobs) {
        try { Stop-Job   -Job $j -EA SilentlyContinue } catch {}
        try { Remove-Job -Job $j -Force -EA SilentlyContinue } catch {}
    }
    $script:Jobs.Clear()

    # v1.5.0: a force-killed job does NOT run its finally, so any still-in-flight
    # target's SYSTEM task + temp files would be orphaned (the task XML carries the
    # -File path to the password-bearing script). Best-effort clean them up over a
    # fresh short-lived DCOM session. Only STARTED (not queued) live jobs are
    # tracked, so this is bounded to <= the concurrency cap, not the whole list.
    $cleanupCred = $script:InheritedCred
    foreach ($e in @($script:JobTasks.GetEnumerator())) {
        $cComp = $e.Value.Computer; $cTask = $e.Value.TaskName
        try {
            $cOpt = New-CimSessionOption -Protocol Dcom
            $cCim = if ($cleanupCred) {
                New-CimSession -ComputerName $cComp -SessionOption $cOpt -Credential $cleanupCred -OperationTimeoutSec 10 -EA Stop
            } else {
                New-CimSession -ComputerName $cComp -SessionOption $cOpt -OperationTimeoutSec 10 -EA Stop
            }
            Unregister-ScheduledTask -TaskName $cTask -Confirm:$false -CimSession $cCim -EA SilentlyContinue
            Remove-CimSession $cCim -EA SilentlyContinue
        } catch {}
        try { Remove-Item -LiteralPath "\\$cComp\C`$\Windows\Temp\$cTask.ps1"           -Force -EA SilentlyContinue } catch {}
        try { Remove-Item -LiteralPath "\\$cComp\C`$\Windows\Temp\SecureBoot_$cComp.json" -Force -EA SilentlyContinue } catch {}
    }
    $script:JobTasks.Clear()

    ## JANET centralized session close (added in v1.4.1). -ShowDialog presents
    ## the JANET closing-notes form so ASI + notes are captured for the rollup.
    try { Stop-JanetSession -ShowDialog } catch {}
})

# ----------------------------------------------------------------------------
# LAUNCH
# ----------------------------------------------------------------------------
$form.Add_Shown({ $form.Activate() })

## JANET centralized session (added in v1.4.1). Metric tool: per-host
## EnableSecureBoot rows recorded in the result harvester; rollup row written
## on FormClosing with dialog.
try { Start-JanetSession -Tool 'SecureBoot' -Version $JanetSecureBootVersion } catch {}

[void]$form.ShowDialog()
$form.Dispose()