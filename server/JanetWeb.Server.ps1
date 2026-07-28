# =============================================================================
#  JanetWeb.Server.ps1  -  the web server for JANET Web
#
#  PURE POWERSHELL. No external modules, nothing to install. Uses only the
#  built-in .NET System.Net.HttpListener that ships with Windows (works on
#  Windows PowerShell 5.1 AND PowerShell 7). Suitable for a locked-down AFNET
#  admin workstation: no PSGallery, no GitHub, no third-party software.
#
#  Binds to 127.0.0.1 ONLY. Every /api request must carry the per-launch token.
#  Static SPA assets (web/) are served openly (UI code, no data). Tool actions
#  run on background runspaces and stream events the browser polls.
#
#  Routes:
#    GET  /                                        -> web/index.html
#    GET  /css/*  /js/*  ...                        -> static assets under web/
#    GET    /api/tools                              -> tool registry (id/name/category/icon)
#    GET/POST/DELETE /api/cred                       -> get/set/clear the session credential
#    POST   /api/session/start                       -> admin-session ack (arms destructive actions)
#    POST   /api/session/end                         -> end the admin session
#    GET    /api/status                              -> server + session status
#    GET/POST /api/target-groups                     -> saved host-list groups
#    GET    /api/logs/tail                            -> tail a tool's log
#    GET    /api/logs/transcript                      -> full session transcript
#    POST   /api/upload                               -> file upload (scan import, packages, ...)
#    GET/POST /api/report-preview                     -> one-shot pre-token report preview link
#    GET    /api/tool/pkginstall/packages             -> pkginstall: list deployable packages
#    GET    /api/tool/pkginstall/msis                 -> pkginstall: list .msi files in a bundle
#    GET    /api/tool/<id>/manifest                   -> per-tool UI manifest
#    POST   /api/tool/<id>/action/<actionId>          -> run a tool action (session-gated if destructive)
#    POST   /api/tool/restart/action/arm-dispatch     -> arm a delayed restart wave (in-memory only)
#    GET    /api/jobs                                 -> live jobs + the armed restart (reattach surface)
#    POST   /api/armed-restart/disarm                 -> stand the armed restart down
#    GET    /api/job/<jobId>/events?since=N           -> poll job progress/events
#    POST   /api/job/<jobId>/cancel                   -> cancel a running job
# =============================================================================

# Resolve a static-asset request URL to a safe file path UNDER the web root, or $null if
# the request must 404. Extracted from the accept loop (loop13) so the path-traversal
# defense is unit-testable in isolation. Byte-for-byte what the loop did inline:
#   - '/' or empty            -> index.html
#   - leaf name starts with _ -> $null (dev/underscore asset never served, audit#28)
#   - Resolve-Path canonicalizes; the resolved path MUST start with "<WebDir>\" (trailing
#     separator so a sibling 'web2' can't prefix-match) AND be an existing leaf file. A
#     '..' escape, absolute path, UNC, missing file, or directory all fall through to $null.
function Get-JanetWebAssetPath {
    param([Parameter(Mandatory)][string]$WebDir, [string]$UrlPath)
    $rel = if ($UrlPath -eq '/' -or [string]::IsNullOrEmpty($UrlPath)) { 'index.html' } else { $UrlPath.TrimStart('/') }
    # audit 2026-07-24 (P3): leaf extraction was [IO.Path]::GetFileName, which on .NET
    # Framework THROWS "Illegal characters in path" for a URL containing < > | or " -
    # the throw unwound to the accept loop's catch, so a malformed URL got a 500 plus a
    # console stack trace instead of a clean 404. Switched to the same pure regex
    # leaf-strip Get-JanetWebSafeUploadName already uses (drop everything up to and
    # including the last / or \): cwd-independent, never throws, identical result for
    # every legal path. Behavior is otherwise unchanged - an illegal-char name simply
    # falls through to the Resolve-Path try/catch below and returns $null (404). The
    # 404 body is the fixed 'not found' string, so no filesystem path is echoed back.
    $leaf = $rel -replace '^.*[\\/]', ''
    if ($leaf -and $leaf.StartsWith('_')) { return $null }
    $full = Join-Path $WebDir ($rel -replace '/', '\')
    $resolved = $null
    try { $resolved = (Resolve-Path -LiteralPath $full -ErrorAction Stop).Path } catch {}
    $webGuard = $WebDir.TrimEnd('\','/') + [System.IO.Path]::DirectorySeparatorChar
    if ($resolved -and $resolved.StartsWith($webGuard, [StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        return $resolved
    }
    return $null
}

# Sanitize an operator-supplied upload filename (X-Janet-Filename header) to a bare,
# traversal-free, device-safe leaf name. Extracted from the /upload handler (loop14) so
# the write-path traversal defense is unit-testable (the twin of Get-JanetWebAssetPath on
# the read path). Always returns a non-empty name; falls back to 'upload.dat'. Steps:
# URL-unescape -> pure leaf extraction -> invalid-char scrub -> empty/dot fallback ->
# reserved-device-name (CON/COM1/...) '_' prefix.
#   loop14 hardening: the inline handler used `Split-Path -Leaf`, which RESOLVES a bare
#   '..' against the provider's current directory (returning a cwd-derived name, so the
#   `-eq '..'` fallback below was silently dead). Switched to a pure regex leaf-strip
#   (drop everything up to and including the last / or \) - cwd-independent AND, unlike
#   [IO.Path]::GetFileName, it never throws on invalid path chars like '<' (which .NET
#   Framework's GetFileName does). So a '..' name deterministically becomes 'upload.dat'.
#   Not a security fix (both outputs were already traversal-free), a determinism fix.
function Get-JanetWebSafeUploadName {
    param([string]$Raw)
    $fname = 'upload.dat'
    if ($Raw) { try { $fname = [System.Uri]::UnescapeDataString($Raw) } catch { $fname = [string]$Raw } }
    $fname = $fname -replace '^.*[\\/]', ''
    foreach ($ch in [System.IO.Path]::GetInvalidFileNameChars()) { $fname = $fname.Replace($ch, '_') }
    if ([string]::IsNullOrWhiteSpace($fname) -or $fname -eq '.' -or $fname -eq '..') { $fname = 'upload.dat' }
    $stem = [System.IO.Path]::GetFileNameWithoutExtension($fname)
    if ($stem -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') { $fname = '_' + $fname }
    return $fname
}

# Sanitize an optional X-Janet-Subdir header (lets a caller co-locate related uploads in
# one folder). Honored ONLY if it is a bare 1-32 char [A-Za-z0-9_-] token that is not a
# reserved device name; anything else (separators, spaces, traversal, too long, empty) ->
# a fresh random 8-hex name. Returns @{ Name=<safe>; Shared=<bool> } (Shared=$true when the
# caller's own name was honored). Extracted for unit testing (loop14).
function Get-JanetWebSafeUploadSubdir {
    param([string]$Raw)
    if ($Raw -and ($Raw -match '\A[A-Za-z0-9_-]{1,32}\z') -and ($Raw -notmatch '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$')) {
        return @{ Name = $Raw; Shared = $true }
    }
    return @{ Name = [guid]::NewGuid().ToString('N').Substring(0,8); Shared = $false }
}

# loop34: mint an access credential from an EXPLICIT cryptographic RNG. The session token and the
# report-preview retrieval key are security credentials (a leak/guess reaches the /api execution
# surface or a rendered report); they were [guid]::NewGuid() which on Windows is CSPRNG-backed but
# relies on that implementation detail rather than a documented crypto contract. This mints 32 bytes
# (256 bits) from RandomNumberGenerator as lowercase hex - an explicit, robust guarantee. The
# (no-modules) launcher mirrors this inline for the session token; keep in lockstep. Pure - tested.
function New-JanetWebSecureToken {
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $bytes = New-Object byte[] 32
        $rng.GetBytes($bytes)
        return (([System.BitConverter]::ToString($bytes)) -replace '-','').ToLowerInvariant()
    } finally { $rng.Dispose() }
}

# audit 2026-07-23: ONE cached UNC reachability gate for every route-level probe on
# the single-threaded accept loop, replacing ~5 hand-rolled regex+probe idioms that
# each paid the UNCACHED 1.5s TCP timeout per request against a dead share. Non-UNC
# paths return $true (local disk can't hang the SMB pre-probe; callers still
# Test-Path the target themselves). Per-HOST cache (~30s) because the routes gate
# several DIFFERENT roots (log share, packages share, arbitrary operator paths) -
# Logging's Test-JanetWebShareCached is a single-slot cache bound to one share root,
# so it would conflate them. Probes via Logging's Test-JanetWebTcpPort (445 only,
# NEVER ICMP - see that helper's AFNET rationale); a probe that THROWS (the logging
# bridge isn't dot-sourced yet during early startup) returns $false UNCACHED,
# matching the old per-site try/catch behavior without poisoning the cache.
$script:JanetWebHostProbeCache = @{}
function Test-JanetWebPathReachable {
    param([string]$Path)
    if ($Path -notmatch '^\\\\([^\\]+)') { return $true }
    $probeHost = $Matches[1]
    $hit = $script:JanetWebHostProbeCache[$probeHost]
    if ($hit -and ((Get-Date) - $hit.At).TotalSeconds -lt 30) { return $hit.Ok }
    $ok = $false
    try { $ok = [bool](Test-JanetWebTcpPort -ComputerName $probeHost -Port 445) } catch { return $false }
    $script:JanetWebHostProbeCache[$probeHost] = @{ At = (Get-Date); Ok = $ok }
    return $ok
}

# =============================================================================
#  ARMED RESTART  -  server-side delayed start for restart/dispatch-restart.
#
#  WHY: the restart tool's "begin at the scheduled time" countdown was a browser
#  setInterval (restart.view.js), so a stray F5 or a closed tab silently lost a
#  2 AM reboot wave - only a beforeunload prompt stood in the way. The countdown
#  now lives on the server process, which has to stay up for the wave anyway.
#
#  This is deliberately NOT a scheduler. Hard boundaries, all of them load-bearing:
#    * restart/dispatch-restart ONLY. There is no generic "arm any action" route -
#      a generic unattended-execution path is a much larger safety problem.
#    * IN-MEMORY ONLY. Nothing about an arm is EVER written to disk: not the
#      params, not the credential (the credential is never in the arm at all -
#      the fire reads $state.Cred, the same in-memory PSCredential a live POST
#      uses), not the fire time. A server restart LOSES the arm. That is correct.
#    * HARD-EXPIRES when the admin session ends (End Session / Clear Credentials
#      drop AckGiven+Cred) or the log-session id changes. Refuses to fire.
#    * REFUSES A STALE FIRE: if the fire time passed more than the grace window
#      ago (console was suspended, laptop slept, clock jumped) the arm expires
#      unfired rather than dumping a 2 AM wave onto a 9 AM fleet.
#    * NO GATE IS WEAKENED. The typed RESTART word, the admin-session gate and
#      every engine-side guard (self-guard, wrong-box guard) still run - the
#      typed word is simply demanded EARLIER, at arm time, and rides inside the
#      stored param set so the ENGINE re-validates it when the wave fires.
#
#  The three functions below are PURE (no state, no I/O) so the expiry/refusal
#  decisions are unit-testable without a listener or a credential.
# =============================================================================

# Longest lead an arm may carry, and how late a fire may still be honored.
$script:JanetWebArmMaxHours     = 24
$script:JanetWebArmGraceMinutes = 10

# Parse an operator-supplied arm time to a local [datetime], or $null if it is
# not a time at all. Mirrors restart.view.js parseRestartTime so the same string
# the operator typed into "Restart time" means the same instant on both sides:
#   'HH:mm' / 'H:mm'  -> the NEXT occurrence (today, or tomorrow if already past)
#   anything else     -> ISO 8601 / 'yyyy-MM-dd HH:mm' via TryParse
function ConvertTo-JanetWebArmFireAt {
    param([string]$Raw, [datetime]$Now = (Get-Date))
    $s = ([string]$Raw).Trim()
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }
    if ($s -match '^(\d{1,2}):(\d{2})$') {
        $hh = [int]$Matches[1]; $mm = [int]$Matches[2]
        if ($hh -gt 23 -or $mm -gt 59) { return $null }
        $d = Get-Date -Year $Now.Year -Month $Now.Month -Day $Now.Day -Hour $hh -Minute $mm -Second 0 -Millisecond 0
        if ($d -le $Now) { $d = $d.AddDays(1) }
        return $d
    }
    $dt = [datetime]::MinValue
    $none = [System.Globalization.DateTimeStyles]::None
    if ([datetime]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, $none, [ref]$dt)) { return $dt }
    if ([datetime]::TryParse($s, [System.Globalization.CultureInfo]::CurrentCulture,   $none, [ref]$dt)) { return $dt }
    return $null
}

# Validate an arm REQUEST. This is where the destructive gate moves EARLIER: the
# typed RESTART word is demanded here, before anything is stored, exactly as the
# engine demands it before a live dispatch. Fail-closed on the dry-run flag: only
# a literal $true / 'true' counts as a dry run, so an odd value is treated as LIVE
# and still needs the word. Returns @{ ok; fireAt; error }.
function Test-JanetWebArmRequest {
    param(
        [hashtable]$Params,
        [string]$FireAtRaw,
        [datetime]$Now = (Get-Date),
        [int]$MaxHours = 24,
        [int]$MinLeadSeconds = 5
    )
    $r = @{ ok = $false; fireAt = $null; dryRun = $false; error = '' }
    if (-not $Params) { $r.error = 'no parameters were supplied for the armed dispatch.'; return $r }
    if ([string]::IsNullOrWhiteSpace([string]$Params['targets'])) { $r.error = 'no targets - an armed dispatch must carry the host list it will fire at.'; return $r }
    $dry = $false
    if ($Params.ContainsKey('dryRun')) {
        $v = $Params['dryRun']
        if (($v -is [bool]) -and $v) { $dry = $true }
        elseif ("$v" -eq 'true' -or "$v" -eq 'True') { $dry = $true }
    }
    $r.dryRun = $dry
    if ((-not $dry) -and (([string]$Params['confirm']).Trim() -cne 'RESTART')) {
        $r.error = 'Refused: type RESTART (exactly) to arm a LIVE dispatch (dry run needs no confirm word). Nothing was armed.'
        return $r
    }
    $fa = ConvertTo-JanetWebArmFireAt -Raw $FireAtRaw -Now $Now
    if (-not $fa) { $r.error = "could not read '$FireAtRaw' as a restart time (use HH:mm or an ISO 8601 date-time)."; return $r }
    if ($fa -le $Now.AddSeconds($MinLeadSeconds)) { $r.error = 'that restart time is in the past - an arm must fire in the future.'; return $r }
    if ($fa -gt $Now.AddHours($MaxHours)) { $r.error = "an armed restart may not be more than $MaxHours hours out (the arm is in memory only and dies with the server)."; return $r }
    $r.ok = $true; $r.fireAt = $fa
    return $r
}

# Build THE arm record. This is the only thing that ever holds an armed wave, and
# it is a plain in-memory hashtable: there is no serializer, no file, no registry
# key, no scheduled task behind it. The credential is deliberately NOT a field -
# the fire reads $state.Cred, exactly as a live POST does, so an arm can never
# outlive (or leak) the credential that authorised it. Pure: constructs and
# returns, touches nothing.
function New-JanetWebArmedRestart {
    param(
        [hashtable]$Params,
        [datetime]$FireAt,
        [string]$SessionId = '',
        [string]$Operator = '',
        [bool]$DryRun = $false,
        [string]$Mode = '',
        [string]$ArmId = ''
    )
    if ([string]::IsNullOrWhiteSpace($ArmId)) { $ArmId = New-JanetWebSecureToken }
    $hosts = @()
    try { $hosts = @(([string]$Params['targets']) -split '[\s,;]+' | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique) } catch {}
    return @{
        ArmId     = $ArmId
        Params    = $Params        # in memory only - never serialized, never written to disk
        FireAt    = $FireAt
        ArmedAt   = Get-Date
        SessionId = [string]$SessionId
        Operator  = [string]$Operator
        HostCount = $hosts.Count
        DryRun    = [bool]$DryRun
        Mode      = [string]$Mode
        Status    = 'armed'
        JobId     = $null
        Reason    = ''
        FiredAt   = $null
    }
}

# Decide what the maintenance tick should do with the current arm. PURE - the
# caller supplies "is the admin session still armed" and the live session id, so
# the refusal paths are testable without a credential. Returns
# @{ fire; expire; reason }. fire and expire are never both $true.
function Test-JanetWebArmShouldFire {
    param(
        $Arm,
        [datetime]$Now = (Get-Date),
        [bool]$SessionArmed = $false,
        [string]$SessionId = '',
        [int]$GraceMinutes = 10
    )
    if (-not $Arm) { return @{ fire = $false; expire = $false; reason = 'nothing armed' } }
    if ([string]$Arm.Status -ne 'armed') { return @{ fire = $false; expire = $true; reason = "the arm is '$([string]$Arm.Status)', not 'armed'." } }
    # The operator ended the admin session (or cleared the credential) after arming.
    # The consent that armed this wave is gone with it - refuse, do not fire.
    if (-not $SessionArmed) { return @{ fire = $false; expire = $true; reason = 'the admin session ended (credential/acknowledgment cleared) after the wave was armed - REFUSING to fire.' } }
    if ([string]$Arm.SessionId -ne [string]$SessionId) { return @{ fire = $false; expire = $true; reason = 'the logging session changed after the wave was armed - REFUSING to fire.' } }
    if ($Now -lt [datetime]$Arm.FireAt) { return @{ fire = $false; expire = $false; reason = 'waiting for the fire time' } }
    if ($Now -gt ([datetime]$Arm.FireAt).AddMinutes($GraceMinutes)) {
        return @{ fire = $false; expire = $true; reason = "the fire time passed more than $GraceMinutes minute(s) ago (the server was stalled/suspended or the clock moved) - REFUSING to fire a stale wave." }
    }
    return @{ fire = $true; expire = $false; reason = 'fire time reached' }
}

function Start-JanetWebServer {
    param(
        [Parameter(Mandatory)] [string]$Root,
        [int]$Port = 8089,
        [Parameter(Mandatory)] [string]$Token,
        [string]$Asi = '',
        [string]$PackagesRoot = ''
    )

    # Fail fast on a misconfigured launch: a Mandatory [string] still accepts ''. With an
    # empty token the request gate at ~:371 never matches ($tok -and ... short-circuits), so
    # EVERY request 403s and the server looks up-but-dead. Throw loudly at start instead.
    # (loop12 server audit P3 - not a bypass, the gate already fails closed; this is clarity.)
    if ([string]::IsNullOrEmpty($Token)) { throw 'Start-JanetWebServer: -Token must be a non-empty per-launch secret.' }
    $serverDir    = Join-Path $Root 'server'
    $webDir       = (Resolve-Path (Join-Path $Root 'web')).Path
    $modulesDir   = Join-Path $Root 'modules'
    $logScript    = Join-Path $serverDir 'JanetWeb.Logging.ps1'
    $authScript   = Join-Path $serverDir 'JanetWeb.Auth.ps1'
    $registryFile = Join-Path $serverDir 'tool-registry.json'

    # Browser-uploaded files land here (one guid subdir per upload). Wiped on each
    # launch so a session never reuses stale temp files. Engines receive the
    # server-side path exactly as if a dialog had returned it.
    #   audit 2026-07-24 (P3): the directory used to be the SHARED %TEMP%\JanetWeb\uploads
    #   and the launch-time wipe below deleted it wholesale - which destroyed a
    #   CONCURRENTLY RUNNING instance's live uploads. Two instances genuinely do coexist:
    #   Resolve-JanetFreePort in the launcher auto-advances 8089..8100 when the port is
    #   busy, so a second launch starts happily beside the first. The port is unique per
    #   live instance (http.sys guarantees it - a second bind on the same port fails), so
    #   scoping the folder per port makes the wipe touch only OUR files. Uploads are
    #   short-lived scratch consumed by the current session, so nothing needs to be shared
    #   across instances.
    $uploadsRoot = Join-Path $env:TEMP 'JanetWeb'
    $uploadsDir  = Join-Path $uploadsRoot ('uploads-{0}' -f $Port)
    try { if (Test-Path -LiteralPath $uploadsDir) { Remove-Item -LiteralPath $uploadsDir -Recurse -Force -ErrorAction SilentlyContinue } } catch {}
    try { New-Item -ItemType Directory -Path $uploadsDir -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
    # Age-based reap of OTHER instances' leftovers (and the pre-fix shared 'uploads'
    # folder), so per-port scoping doesn't just trade one bug for unbounded temp growth.
    # Never touches our own folder.
    #   audit 2026-07-25 (fable re-audit follow-up): age alone was NOT safe, and the
    #   comment here claimed it was ("a still-running peer's folder is younger than 24 h
    #   even if idle"). False: LastWriteTime is stamped at the peer's LAUNCH and on each
    #   upload, so a peer running longer than a day with no upload in the last 24 h had
    #   its LIVE uploads-<port> directory deleted out from under it by a new instance's
    #   launch. A port-scoped folder is now reaped only when it is BOTH older than 24 h
    #   AND its port is not currently bound: http.sys holds the port for the whole life
    #   of a peer (that is exactly why the folder is keyed by port), so a bound port is
    #   proof of life no idle period can fake. If the listener table can't be read we
    #   leave the port-scoped folders alone and let a later launch reap them - a day of
    #   extra temp files is cheaper than eating a live session's uploads. The legacy
    #   portless 'uploads' folder is never live under this build, so age alone retires it.
    try {
        $listenPorts = $null
        try { $listenPorts = @([System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners() | ForEach-Object { [int]$_.Port }) } catch { $listenPorts = $null }
        Get-ChildItem -LiteralPath $uploadsRoot -Directory -Filter 'uploads*' -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -ne $uploadsDir -and $_.LastWriteTime -lt (Get-Date).AddHours(-24) } |
            Where-Object {
                if ($_.Name -match '^uploads-(\d+)$') {
                    if ($null -eq $listenPorts) { return $false }               # liveness unknowable -> keep
                    return (-not ($listenPorts -contains [int]$Matches[1]))     # port bound = peer alive -> keep
                }
                return $true                                                    # legacy portless folder
            } |
            ForEach-Object { try { Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue } catch {} }
    } catch {}

    # Server-persisted TargetManager saved groups (was browser localStorage). Lives
    # in the in-repo JanetLocal runtime-state dir so named host groups survive a
    # browser wipe / a different launch port and ride along in take-to-work. Gitignored
    # (JanetLocal/*); not seeded - starts absent, GET returns {} until the first save.
    $targetGroupsFile = Join-Path (Join-Path $Root 'JanetLocal') 'target-groups.json'

    # Where the Remote Package Installer lists packages from (the dropdown source).
    # Resolution: explicit -PackagesRoot wins; else the local .\Packages when it
    # holds packages; else the work share (where the content lives at work) when
    # reachable; else the local folder. The local folder is always created+seeded
    # below so its Log4j staging path + README exist no matter what we read from.
    $JanetPackageShare = '\\dm-tn-01\sh-usafe-automation$\JANET\Packages'
    $localPackages = Join-Path $Root 'Packages'
    try { if (-not (Test-Path -LiteralPath $localPackages)) { New-Item -ItemType Directory -Path $localPackages -Force -ErrorAction SilentlyContinue | Out-Null } } catch {}
    if (-not [string]::IsNullOrWhiteSpace($PackagesRoot)) {
        $packagesDir = $PackagesRoot
    } else {
        $packagesDir = $localPackages
        # "Has packages" = any subfolder other than the seeded Log4j staging dir.
        $localHasPkgs = $false
        try { $localHasPkgs = [bool](Get-ChildItem -LiteralPath $localPackages -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'Log4j' } | Select-Object -First 1) } catch {}
        if (-not $localHasPkgs) {
            # audit 2026-07-23: shared cached probe helper (a thrown probe - the logging
            # bridge isn't dot-sourced yet here - still resolves $false, exactly like the
            # old per-site try/catch did).
            if ((Test-JanetWebPathReachable $JanetPackageShare) -and (Test-Path -LiteralPath $JanetPackageShare)) { $packagesDir = $JanetPackageShare }
        }
    }
    Write-Host ("  Packages: $packagesDir") -ForegroundColor DarkGray
    # Export the resolved packages root so worker runspaces (e.g. patchlib inventory,
    # which honors a -PackagesRoot override) inherit the same folder the server chose.
    # Operator environments that still set the TWO-era JANET2_PACKAGES_ROOT keep
    # working: Get-PatchlibRoots falls back to the old name when this one is unset.
    $env:JANETWEB_PACKAGES_ROOT = $packagesDir
    # Local Log4j staging folder (always seeded under the local .\Packages, even
    # when we READ packages from the share - the on-box default the ACAS Log4j
    # jar-replace falls back to; drop the jars here or point at the share).
    try {
        $log4jStage = Join-Path (Join-Path $localPackages 'Log4j') 'NewFiles'
        if (-not (Test-Path -LiteralPath $log4jStage)) { New-Item -ItemType Directory -Path $log4jStage -Force -ErrorAction SilentlyContinue | Out-Null }
        $log4jReadme = Join-Path $log4jStage 'README.txt'
        if (-not (Test-Path -LiteralPath $log4jReadme)) {
            Set-Content -LiteralPath $log4jReadme -Encoding UTF8 -ErrorAction SilentlyContinue -Value @(
                'ACAS Nemesis - Log4j staging',
                '',
                'Drop the two patched jars here:',
                '  log4j-api-2.25.4.jar',
                '  log4j-core-2.25.4.jar',
                '',
                'This folder is the DEFAULT Log4j source for JANET Web - no need to set anything.',
                'Grab the two jars from the desktop staging share and drop them here:',
                '  \\dm-tn-01\sh-usafe-automation$\JANET\Packages\Log4j\NewFiles',
                '',
                'The JANET Web host copies these jars into each target session (no remote',
                'double-hop) and replaces the vulnerable jars in the HID/Adobe lib paths.',
                'To use a different source, set the path in the ACAS tool''s "Log4j Source".'
            )
        }
    } catch {}

    . $logScript
    . $authScript

    # --- catalog: registry + live manifests for every registered tool (load in
    #     isolation, because every tool module exports the same two function names) -
    $registry = Get-Content -LiteralPath $registryFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $manifests = @{}; $modulePaths = @{}
    foreach ($t in $registry.tools) {
        $mp = Join-Path $modulesDir ("JanetWeb.{0}.psm1" -f $t.id)
        if (-not (Test-Path -LiteralPath $mp)) { continue }
        try {
            Import-Module $mp -Force -ErrorAction Stop
            $manifests[$t.id] = Get-JanetToolManifest
            $modulePaths[$t.id] = $mp
            Remove-Module ("JanetWeb.{0}" -f $t.id) -Force -ErrorAction SilentlyContinue
        } catch { Write-Warning "JANET Web: module '$($t.id)' failed to load: $($_.Exception.Message)" }
    }

    $state = @{
        Cred        = $null
        AckGiven    = $false   # responsibility acknowledgment (set via /api/session/start)
        Jobs        = [hashtable]::Synchronized(@{})
        JobSeq      = 0
        LogCtx      = (New-JanetWebLogContext -Operator $env:USERNAME -Asi $Asi -Version '1.0.0' -JanetRoot (Split-Path -Parent $Root))
        LogScript   = $logScript
        ModulePaths = $modulePaths
        Manifests   = $manifests
        Registry    = $registry
        ClosingNotes = ''
        ArchivedCsvs = (New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase))
        # toolId -> @{ RS=<persistent Runspace>; Busy=$bool } for stateful tools
        # (currently reports) whose engines cache $script: state across actions.
        # Created lazily on first action; the module + logging script are imported
        # once so parse/scan state survives the render/export actions.
        ToolRunspaces = @{}
        # One-shot report-preview stash: id (unguessable GUID) -> @{ Html; At }.
        # POST /api/report-preview fills it; GET /api/report-preview?id= serves it
        # once (deleted on read, 5-min TTL) with its own relaxed CSP. Accept-thread
        # only, so a plain hashtable is safe.
        ReportPreviews = @{}
        # THE armed restart (at most one, restart/dispatch-restart only) or $null.
        # Accept-thread only. IN-MEMORY ONLY - see the ARMED RESTART block above:
        # this slot is never serialized, never written to disk, and dies with the
        # process. Shape: @{ ArmId; Params; FireAt; ArmedAt; SessionId; Operator;
        #                    HostCount; DryRun; Mode; Status; JobId; Reason }
        ArmedRestart = $null
        # The last arm that left the slot (fired / expired / disarmed), kept only so
        # the console + a reconnecting UI can explain what happened to it. Also
        # in-memory only.
        LastFiredArm = $null
    }

    # Armed-restart tuning, captured into LOCALS at start. The $script: defaults
    # above are the single source of truth, but reading them once here means the
    # arm gate can never silently degrade to 0 hours / 0 minutes of grace if this
    # file is ever loaded into a scope where $script: resolves elsewhere.
    $armMaxHours = [int]$script:JanetWebArmMaxHours;     if ($armMaxHours -le 0) { $armMaxHours = 24 }
    $armGraceMin = [int]$script:JanetWebArmGraceMinutes; if ($armGraceMin -le 0) { $armGraceMin = 10 }

    # --- helpers ---------------------------------------------------------------
    $contentType = {
        param($ext)
        switch ($ext.ToLower()) {
            '.html' { 'text/html; charset=utf-8' }
            '.css'  { 'text/css; charset=utf-8' }
            '.js'   { 'application/javascript; charset=utf-8' }
            '.json' { 'application/json; charset=utf-8' }
            '.svg'  { 'image/svg+xml' }
            '.png'  { 'image/png' }
            '.ico'  { 'image/x-icon' }
            default { 'application/octet-stream' }
        }
    }
    $writeBytes = {
        param($resp, [byte[]]$bytes, [int]$code, [string]$ctype, [string]$csp)
        try {
            $resp.StatusCode = $code
            $resp.ContentType = $ctype
            # Additive hardening (every response, static + JSON): keep the per-launch
            # token out of any Referer to sub-resources, and turn off MIME sniffing.
            # Each header set is independently guarded - setting can throw on some states.
            try { $resp.Headers['Referrer-Policy'] = 'no-referrer' } catch {}
            try { $resp.Headers['X-Content-Type-Options'] = 'nosniff' } catch {}
            # Defense-in-depth (loopback + token is the real gate): forbid framing and
            # pin resources to same-origin. The one inline <script> in index.html (the
            # pre-paint theme set) is allowed by its exact sha256 so injected inline
            # scripts stay blocked; style-src keeps 'unsafe-inline' (the SPA sets style
            # attributes); img/frame allow data: (inline icons). A caller may pass its
            # own $csp - the /api/report-preview route needs 'unsafe-inline' script-src
            # so the GENERATED report's inline <script> (no fixed hash) runs; that page
            # can't reuse this strict default (nor a data: URI, which would inherit it).
            try { $resp.Headers['X-Frame-Options'] = 'DENY' } catch {}
            if ([string]::IsNullOrEmpty($csp)) {
                $csp = "default-src 'self'; script-src 'self' 'sha256-dXcyG9/YViVo9dfNzcP9EoapNRFMTxHCcy214aTUYEk='; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"
            }
            try { $resp.Headers['Content-Security-Policy'] = $csp } catch {}
            $resp.ContentLength64 = $bytes.Length
            $resp.OutputStream.Write($bytes, 0, $bytes.Length)
        } catch {} finally { try { $resp.OutputStream.Close() } catch {} }
    }
    $writeJson = {
        param($resp, $obj, [int]$code = 200)
        $json = if ($null -eq $obj) { 'null' } else { $obj | ConvertTo-Json -Depth 24 -Compress }
        & $writeBytes $resp ([System.Text.Encoding]::UTF8.GetBytes($json)) $code 'application/json; charset=utf-8'
    }

    # Drain ONE finished worker: EndInvoke + Dispose its [powershell], finalize a
    # raced cancel, and free the stateful tool's serialized Busy slot. One shared
    # scriptblock for the reaper below AND the events-poll fast path (audit
    # 2026-07-23: the logic was duplicated at both sites, and both carried a dead
    # $job.RS close branch - RS is never assigned on job hashtables - now deleted).
    $drainJob = {
        param($j)
        if ($j.Status -ne 'running' -and $j.PS -and $j.Async -and $j.Async.IsCompleted) {
            try { $j.PS.EndInvoke($j.Async) | Out-Null } catch {}
            try { $j.PS.Dispose() } catch {}   # disposes the [powershell] only; a persistent tool runspace is assigned, not owned, so it stays open
            $j.PS = $null; $j.Async = $null
            # cancel raced the worker's own completion: the worker is gone, so
            # nothing else will ever map 'cancelling' to a terminal status
            if ($j.Status -eq 'cancelling') { $j.Status = 'cancelled' }
            # free the stateful tool's serialized slot for the next action
            if ($j.Tool -and $state.ToolRunspaces.ContainsKey($j.Tool)) { $state.ToolRunspaces[$j.Tool].Busy = $false }
        }
    }

    # Reaper: drain finished workers' runspaces (so $job.PS doesn't leak when the
    # client stops polling), free stateful Busy slots, and evict jobs 5 min after
    # they FINISH (FinishedAt, not StartedAt - a job running >5 min must survive
    # to deliver its final summary). Invoked from the maintenance tick, the events
    # route, the action POST route and the cancel route. $keepJobId: the job the
    # current request is about - never evicted in the same pass.
    $reapJobs = {
        param([string]$keepJobId)
        foreach ($k in @($state.Jobs.Keys)) {
            $j = $state.Jobs[$k]
            if (-not $j) { continue }
            & $drainJob $j
            # 'cancelling' counts as live: the worker is still draining its abandon
            # events and will stamp FinishedAt when it maps itself to 'cancelled'.
            if ($j.Status -eq 'running' -or $j.Status -eq 'cancelling') { continue }
            if (-not $j.FinishedAt) { $j.FinishedAt = Get-Date }   # backstop for any path that missed the stamp
            if (-not $j.PS -and $k -ne $keepJobId -and ((Get-Date) - $j.FinishedAt).TotalMinutes -gt 5) { [void]$state.Jobs.Remove($k) }
        }
    }

    # Create and START one tool-action job: mint the job record, spawn the worker
    # runspace, and BeginInvoke it. This IS the body of POST /api/tool/<id>/action/
    # <actionId> (extracted, byte-for-byte apart from the transport lines) so that
    # the armed-restart tick can launch a wave through the EXACT same code path the
    # HTTP route uses - one job-start path, one set of guards, no second copy to
    # drift. Transport-free: it never touches $resp, it RETURNS the outcome:
    #     @{ ok = $true;  jobId = <id> }
    #     @{ ok = $false; code = <http status>; error = <client-safe message> }
    $startToolJob = {
        param([string]$toolId, [string]$actId, [hashtable]$actionParams, [string]$toolVer, $mani, [string]$mp)
        $state.JobSeq++
        $jobId = "j$($state.JobSeq)_$([guid]::NewGuid().ToString('N').Substring(0,6))"
        $job = [hashtable]::Synchronized(@{
            Id=$jobId; Tool=$toolId; Action=$actId
            Events=([System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList)))
            Status='running'; Result=$null; PS=$null; Async=$null; StartedAt=(Get-Date); FinishedAt=$null; Cancel=$false
        })
        $state.Jobs[$jobId] = $job
        # Hand the (synchronized) job to the engine so a long fan-out can poll
        # its Cancel flag and stop in-flight WinRM children when the operator
        # presses Cancel. Engines that don't look for '__job' just ignore it.
        $actionParams['__job'] = $job

        $worker = {
            param($modulePath, $actionId, $prms, $cred, $job, $logScript, $logCtx, $toolId, $skipImport, $toolVer, $archivedCsvs)
            try {
                # Stateful tools run in a persistent runspace where the module +
                # logging script were imported ONCE at runspace creation;
                # re-importing would reset $script: state, so skip it for them.
                if (-not $skipImport) {
                    . $logScript
                    Import-Module $modulePath -Force -ErrorAction Stop
                }
                # ACAS: retain a timestamped archive copy of each uploaded CSV (once
                # per unique source) next to this operator's ACAS logs - an audit
                # trail of exactly what was imported. Best-effort; never blocks or
                # fails the action. audit 2026-07-23: ran on the single-threaded
                # accept loop before - moved here so a slow share Copy-Item can't
                # stall every request. $archivedCsvs (the server's once-per-source
                # set) is now shared across concurrent worker runspaces: hold its
                # monitor for the whole pass (rare + best-effort, so coarse is fine).
                if ($toolId -eq 'acas' -and $prms['csvPaths'] -and $null -ne $archivedCsvs) {
                    [System.Threading.Monitor]::Enter($archivedCsvs)
                    try {
                        $archRoot = if ($logCtx.OnShare) { $logCtx.NetRoot } else { $logCtx.JanetLocal }
                        # The DESTINATION can be a share too - ping-gate it like the
                        # UNC sources below. The throw lands in this block's empty
                        # catch: archiving is skipped this pass and (since nothing
                        # was added to $archivedCsvs) retried on the next action.
                        if ($archRoot -match '^\\\\([^\\]+)') {
                            if (-not (Test-JanetWebHostReachable $Matches[1])) { throw 'archive share unreachable' }
                        }
                        $archDir = Join-Path (Join-Path (Join-Path $archRoot (Resolve-JanetWebToolName -ToolId 'acas')) $logCtx.UserFolder) 'CsvArchive'
                        foreach ($cp in ([string]$prms['csvPaths'] -split "`r?`n")) {
                            $src = $cp.Trim().Trim('"'); if (-not $src) { continue }
                            if ($archivedCsvs.Contains($src)) { continue }
                            # Uploaded CSVs are local temp paths (fast). A manually-typed
                            # UNC source is still ping-gated first: worker time is cheap,
                            # but a bounded probe beats a 30s SMB stall even here.
                            if ($src -match '^\\\\([^\\]+)') {
                                if (-not (Test-JanetWebHostReachable $Matches[1])) { [void]$archivedCsvs.Add($src); continue }
                            }
                            if (-not (Test-Path -LiteralPath $src)) { continue }
                            # audit 2026-07-28: the Add used to sit HERE, before the two
                            # -ErrorAction Stop calls below. A transient copy failure
                            # (ACL hiccup, share drops after the cached probe, long dest
                            # path) therefore marked the file archived for the LIFE OF THE
                            # PROCESS with nothing on disk, and - because the throw escaped
                            # the loop to the outer empty catch - abandoned the remaining
                            # CSVs in the same pass too. Silent and permanent: the uploads
                            # are wiped on the next server start. Now the marker is only
                            # set after a real copy, and one file's failure no longer
                            # aborts its siblings. The unreachable-UNC Add above stays
                            # where it is - that one is a "do not re-probe a dead host"
                            # marker, not a success marker.
                            try {
                                if (-not (Test-Path -LiteralPath $archDir)) { New-Item -ItemType Directory -Path $archDir -Force -ErrorAction Stop | Out-Null }
                                $dest = Join-Path $archDir ((Get-Date -Format 'yyyy-MM-dd_HHmmss') + '_' + (Split-Path -Leaf $src))
                                Copy-Item -LiteralPath $src -Destination $dest -Force -ErrorAction Stop
                                [void]$archivedCsvs.Add($src)
                            } catch {}
                        }
                    } catch {} finally { [System.Threading.Monitor]::Exit($archivedCsvs) }
                }
                # The manifest ToolVersion rides to the audit CSV only when the
                # loaded logging bridge has the (optional) parameter, so the two
                # changes can land in either order.
                # Tools whose audit target IS a machine -> they get a per-host TouchedHosts
                # CSV. Excluded BY POLICY, not by target shape: reports (filenames),
                # adsearch/adto (directory objects/DNs), dhcp (its targets ARE server
                # hostnames, but its read-only "listed N scope(s)" rows would inflate the
                # freshness trail - the same reason biosfirmware dropped its scan emit on
                # 2026-07-23), and the read-only cohort (history/sysadmin/patchlib/kev)
                # which deliberately emits no audit rows at all.
                # audit 2026-07-28: c2c, certdeploy and winrmbridge had DRIFTED off this
                # list - each emits a host-targeted audit row on a destructive path
                # (c2c pillar fixes, certdeploy root-store install, winrmbridge SYSTEM
                # scheduled task + 5986 listener) but got no attribution row. They were
                # added to the suite AFTER this list was last hand-edited and nobody
                # amended it. Adding the three ids deliberately, rather than deriving the
                # list from the host-key shape test: a derived rule would newly enroll
                # dhcp, adsearch and reports, whose targets pass the shape test.
                $hostTouchingTool = @('wpt','acas','pkginstall','winupgrade','upr','secureboot','restart','message','remoteadmin','c2c','certdeploy','winrmbridge') -contains $toolId
                $emit = {
                    param($e)
                    [void]$job.Events.Add($e)
                    if ($e.type -eq 'audit') {
                        if ($e.action -ne 'TouchHost' -and $e.action -ne 'VulnPatched') {
                            # Honest: an action outside the ValidateSet would be dropped by
                            # Write-JanetAction without a trace. Surface it (engine bug to fix).
                            [void]$job.Events.Add(@{ type='log'; level='warn'; text="Audit NOT recorded: action '$([string]$e.action)' is outside the ValidateSet (TouchHost/VulnPatched) - Tool=$toolId Target=$([string]$e.target). Engine must emit a valid action." })
                        } else {
                        try {
                            $wja = @{ Context=$logCtx; Tool=$toolId; Action=$e.action; Target=$e.target; Result=$e.result; ItemCount=([int]$e.itemCount); Detail=([string]$e.detail); ToolVersion=$toolVer }
                            Write-JanetAction @wja
                        } catch { [void]$job.Events.Add(@{ type='log'; level='warn'; text="Audit row write failed (Tool=$toolId Action=$([string]$e.action) Target=$([string]$e.target)): $($_.Exception.Message)" }) }
                        }
                        # Per-session .log transcript for EVERY tool (desktop parity:
                        # each tool keeps a human-readable record of what it did).
                        try { Write-JanetWebSessionLog -Context $logCtx -Tool $toolId -Action ([string]$e.action) -Target ([string]$e.target) -Result ([string]$e.result) -Detail ([string]$e.detail) } catch {}
                        # Per-host attribution CSV (TouchedHosts_<month>.csv) for every
                        # host-touching tool, so a lead can pivot "which machines did op X
                        # touch this month". Skipped for non-host targets / non-host tools.
                        if ($hostTouchingTool) {
                            # audit 2026-07-28: this carried only the historical 2-literal
                            # blacklist plus an inline split, while its sibling in the
                            # logging bridge used the full predicate - so WPT's OU-import
                            # sentinel '(ActiveDirectory)' passed here and wrote a per-host
                            # attribution row for a machine that does not exist. That is the
                            # SAME defect the 2026-07-24 pass fixed for remoteadmin's
                            # '(run-script)', in the one site it did not touch. Both sites
                            # now share Resolve-JanetWebHostKey and cannot diverge again.
                            $thHost = Resolve-JanetWebHostKey -Target ([string]$e.target)
                            if ($thHost) {
                                try { Write-JanetWebTouchedHost -Context $logCtx -Tool $toolId -Action ([string]$e.action) -TargetHost $thHost -Result ([string]$e.result) -Detail ([string]$e.detail) } catch {}
                            }
                        }
                    }
                    elseif ($e.type -eq 'run' -and $toolId -eq 'acas') {
                        # Per-run summary -> daily ACAS-Nemesis-Runs CSV (desktop Write-NemRunSummary).
                        try {
                            $members = @(); if ($e.groupMembers) { $members = @($e.groupMembers) }
                            Write-JanetWebRun -Context $logCtx -Tool $toolId -Action ([string]$e.action) -Scope ([string]$e.scope) `
                                -Profile ([string]$e.profile) -Mode ([string]$e.mode) -HostsTotal ([int]$e.hostsTotal) `
                                -Success ([int]$e.success) -Failed ([int]$e.failed) -DurationSec ([int]$e.durationSec) `
                                -GroupKey ([string]$e.groupKey) -GroupMembers $members
                        } catch {}
                    }
                }.GetNewClosure()
                # Per-action transcript backstop: log the START and END of EVERY action
                # invocation to this tool's .log, so even an action that emits no
                # fine-grained audit still leaves a durable trace. This is what makes
                # "everything JANET Web does is logged" literally true.
                $actStart = Get-Date
                $paramKeys = ''
                try { $paramKeys = (@($prms.Keys | Where-Object { $_ -ne '__job' }) | Sort-Object) -join ', ' } catch {}
                try { Write-JanetWebSessionLog -Context $logCtx -Tool $toolId -Action "ACTION:$actionId" -Target '(start)' -Result 'Started' -Detail $paramKeys } catch {}
                $res = Invoke-JanetToolAction -ActionId $actionId -Params $prms -Credential $cred -Emit $emit
                [void]$job.Events.Add(@{ type='final'; result=$res })
                $job.Result = $res
                if ($job.Status -eq 'running') { $job.Status = 'done' }                  # don't clobber a cancel
                elseif ($job.Status -eq 'cancelling') { $job.Status = 'cancelled' }      # abandon events all emitted - now terminal
                try {
                    $durs = [math]::Round(((Get-Date) - $actStart).TotalSeconds, 1)
                    Write-JanetWebSessionLog -Context $logCtx -Tool $toolId -Action "ACTION:$actionId" -Target '(end)' -Result ([string]$job.Status) -Detail "duration=${durs}s"
                } catch {}
            } catch {
                $errMsg = $_.Exception.Message
                [void]$job.Events.Add(@{ type='error'; text=$errMsg })
                if ($job.Status -eq 'running') { $job.Status = 'error' }
                elseif ($job.Status -eq 'cancelling') { $job.Status = 'cancelled' }
                # Persist the failure to the share (shared detail CSV + the .log) so a
                # thrown action is never silently lost - it was, before this.
                try {
                    $wjaErr = @{ Context=$logCtx; Tool=$toolId; Action='TouchHost'; Target='N/A'; Result='Failure'; ItemCount=0; Detail="action '$actionId' failed: $errMsg"; ToolVersion=$toolVer }
                    Write-JanetAction @wjaErr
                } catch {}
                try { Write-JanetWebSessionLog -Context $logCtx -Tool $toolId -Action "ACTION:$actionId" -Target '(end)' -Result 'Error' -Detail $errMsg } catch {}
            }
            $job.FinishedAt = Get-Date   # eviction clock starts at FINISH, not start
        }
        # Stateful tools (those whose manifest sets statefulRunspace,
        # currently reports) reuse ONE persistent, module-loaded runspace so
        # their $script: parse/scan state survives across actions - serialized
        # to one action at a time. The flag is the single source of truth.
        $stateful = ($mani -and $mani.statefulRunspace)
        if ($stateful) {
            if (-not $state.ToolRunspaces.ContainsKey($toolId)) {
                try {
                    $trs = [runspacefactory]::CreateRunspace(); $trs.ApartmentState = 'STA'; $trs.ThreadOptions = 'ReuseThread'; $trs.Open()
                    $initPs = [powershell]::Create(); $initPs.Runspace = $trs
                    [void]$initPs.AddScript('param($ls,$mp) . $ls; Import-Module $mp -Force -ErrorAction Stop').AddArgument($state.LogScript).AddArgument($mp)
                    $initPs.Invoke() | Out-Null; $initPs.Dispose()
                    $state.ToolRunspaces[$toolId] = @{ RS = $trs; Busy = $false }
                } catch {
                    $ex = $_
                    [void]$state.Jobs.Remove($jobId)
                    try { Write-Host ("  [500] start $toolId runspace -> $($ex.Exception.Message)`r`n$($ex.ScriptStackTrace)") -ForegroundColor Red } catch {}
                    return @{ ok = $false; code = 500; error = 'internal error - see server console' }
                }
            }
            $slot = $state.ToolRunspaces[$toolId]
            if ($slot.Busy) {
                [void]$state.Jobs.Remove($jobId)
                return @{ ok = $false; code = 409; error = "$toolId is busy with another action - wait for it to finish, then retry." }
            }
            $slot.Busy = $true
            $ps = [powershell]::Create(); $ps.Runspace = $slot.RS
            [void]$ps.AddScript($worker).AddArgument($mp).AddArgument($actId).AddArgument($actionParams).AddArgument($state.Cred).AddArgument($job).AddArgument($state.LogScript).AddArgument($state.LogCtx).AddArgument($toolId).AddArgument($true).AddArgument($toolVer).AddArgument($state.ArchivedCsvs)
        } else {
            $ps = [powershell]::Create()
            [void]$ps.AddScript($worker).AddArgument($mp).AddArgument($actId).AddArgument($actionParams).AddArgument($state.Cred).AddArgument($job).AddArgument($state.LogScript).AddArgument($state.LogCtx).AddArgument($toolId).AddArgument($false).AddArgument($toolVer).AddArgument($state.ArchivedCsvs)
        }
        # Transactional start: if BeginInvoke throws (dead persistent
        # runspace, OOM), free the stateful Busy slot and drop the job so
        # the reaper isn't left a stuck 'running' job with no live Async
        # (which would 409-block reports for the rest of the session).
        $job.PS = $ps
        try {
            $job.Async = $ps.BeginInvoke()
        } catch {
            $ex = $_
            try { $ps.Dispose() } catch {}
            [void]$state.Jobs.Remove($jobId)
            if ($stateful -and $slot) { $slot.Busy = $false }
            try { Write-Host ("  [500] start job -> $($ex.Exception.Message)`r`n$($ex.ScriptStackTrace)") -ForegroundColor Red } catch {}
            return @{ ok = $false; code = 500; error = 'internal error - see server console' }
        }
        return @{ ok = $true; jobId = $jobId }
    }

    # Client-facing view of an armed restart: identity, counts and times ONLY. The
    # stored param set (the host list, the countdown message, the typed confirm
    # word) is deliberately NOT echoed back - the UI needs to SHOW that a wave is
    # armed and be able to DISARM it, nothing more. Returns $null when nothing is armed.
    $armSummary = {
        param($arm)
        if (-not $arm) { return $null }
        return @{
            armId     = [string]$arm.ArmId
            tool      = 'restart'
            action    = 'dispatch-restart'
            status    = [string]$arm.Status
            fireAt    = ([datetime]$arm.FireAt).ToString('o')
            armedAt   = ([datetime]$arm.ArmedAt).ToString('o')
            hostCount = [int]$arm.HostCount
            dryRun    = [bool]$arm.DryRun
            mode      = [string]$arm.Mode
            operator  = [string]$arm.Operator
            secondsRemaining = [int][math]::Max(0, [math]::Round(((([datetime]$arm.FireAt) - (Get-Date)).TotalSeconds)))
        }
    }

    # Armed-restart maintenance tick. Runs on EVERY accept-loop pass - each request
    # AND each 2 s heartbeat - following the cheap-hook pattern of
    # Write-JanetWebUsageSnapshot: no new poller, no timer, no extra thread, and it
    # NEVER THROWS (a fault here must not take down the accept loop).
    #
    # Every fire/expire decision belongs to the PURE Test-JanetWebArmShouldFire
    # above, so the refusal paths are unit-testable without a listener or a
    # credential. This block only CARRIES OUT that decision:
    #   expire -> drop the arm and say so loudly (console + the restart transcript)
    #   fire   -> launch through $startToolJob, the exact same path
    #             POST /api/tool/restart/action/dispatch-restart takes, with the
    #             same in-memory $state.Cred. The stored param set still carries the
    #             typed RESTART word, so the ENGINE re-validates it on the way in.
    $tickArmedRestart = {
        try {
            $arm = $state.ArmedRestart
            if (-not $arm) { return }
            $sessionArmed = ($state.AckGiven -and $null -ne $state.Cred)
            $d = Test-JanetWebArmShouldFire -Arm $arm -Now (Get-Date) -SessionArmed $sessionArmed `
                    -SessionId ([string]$state.LogCtx.SessionId) -GraceMinutes $armGraceMin
            if ($d.expire) {
                $arm.Status = 'expired'; $arm.Reason = [string]$d.reason
                $state.ArmedRestart = $null
                $state.LastFiredArm = $arm
                try { Write-Host ("  [armed restart] EXPIRED - NOT fired: $($d.reason)") -ForegroundColor Yellow } catch {}
                try { Write-JanetWebSessionLog -Context $state.LogCtx -Tool 'restart' -Action 'ARM:expired' -Target "(armed dispatch - $([int]$arm.HostCount) host(s))" -Result 'Expired' -Detail ([string]$d.reason) } catch {}
                return
            }
            if (-not $d.fire) { return }
            $mani = $state.Manifests['restart']; $mp = $state.ModulePaths['restart']
            if (-not $mp) {
                $arm.Status = 'expired'; $arm.Reason = 'the restart module is not loaded on this server'
                $state.ArmedRestart = $null; $state.LastFiredArm = $arm
                try { Write-Host '  [armed restart] EXPIRED - NOT fired: the restart module is not loaded.' -ForegroundColor Red } catch {}
                return
            }
            $armToolVer = '1.0.0'; if ($mani -and $mani.version) { $armToolVer = [string]$mani.version }
            # Clear the slot BEFORE launching. A throw or a failed start must never
            # leave a live arm behind for the NEXT tick to fire a second time.
            $state.ArmedRestart = $null
            $jr = & $startToolJob 'restart' 'dispatch-restart' $arm.Params $armToolVer $mani $mp
            if ($jr -is [array]) { $jr = $jr[-1] }
            if ($jr -and $jr.ok) {
                $arm.Status = 'fired'; $arm.JobId = [string]$jr.jobId; $arm.FiredAt = Get-Date
                $state.LastFiredArm = $arm
                try { Write-Host ("  [armed restart] FIRING NOW - $([int]$arm.HostCount) host(s), job $([string]$jr.jobId)") -ForegroundColor Cyan } catch {}
                try { Write-JanetWebSessionLog -Context $state.LogCtx -Tool 'restart' -Action 'ARM:fired' -Target "(armed dispatch - $([int]$arm.HostCount) host(s))" -Result 'Fired' -Detail ("job=$([string]$jr.jobId) armedAt=$(([datetime]$arm.ArmedAt).ToString('s'))") } catch {}
            } else {
                $arm.Status = 'failed'; $arm.Reason = [string]$jr.error
                $state.LastFiredArm = $arm
                try { Write-Host ("  [armed restart] FAILED to start: $([string]$jr.error)") -ForegroundColor Red } catch {}
                try { Write-JanetWebSessionLog -Context $state.LogCtx -Tool 'restart' -Action 'ARM:failed' -Target '(armed dispatch)' -Result 'Failure' -Detail ([string]$jr.error) } catch {}
            }
        } catch {
            # Fail CLOSED: an unexpected fault drops the arm rather than leaving a
            # wave that might fire on some later, less-understood pass.
            $state.ArmedRestart = $null
            try { Write-Host ("  [armed restart] tick error - arm DISCARDED: $($_.Exception.Message)") -ForegroundColor Red } catch {}
        }
    }

    # Read a request body as UTF-8 text. PS 5.1's $req.ContentEncoding falls back
    # to ANSI when the charset is absent and fetch always sends UTF-8. Bounded
    # stream-copy so a chunked body (ContentLength64 = -1) can't bypass the cap.
    $readBody = {
        param($req, [long]$cap)
        if (-not $req.HasEntityBody) { return '' }
        $ms = New-Object System.IO.MemoryStream
        try {
            $buf = New-Object byte[] 81920
            $total = 0L
            while (($read = $req.InputStream.Read($buf, 0, $buf.Length)) -gt 0) {
                $total += $read
                if ($total -gt $cap) { throw "request body exceeded the $([int]($cap/1MB)) MB cap" }
                $ms.Write($buf, 0, $read)
            }
            return [System.Text.Encoding]::UTF8.GetString($ms.ToArray())
        } finally { $ms.Dispose() }
    }

    # ACAS drives part of its UI through fixed action ids that are intentionally
    # not in the manifest; every other action id must match the tool's manifest.
    $acasByIdActions = @('patch-selected','schedule-reboot','verify-post-reboot','preflight-services','group-findings','list-profiles','findings-for-host','reboot-selected','verify-selected')
    # Of the by-id set, these change machine state (WinRM patch push / shutdown /r)
    # and MUST pass the same admin-session gate as manifest destructive actions.
    $acasByIdDestructive = @('patch-selected','reboot-selected','schedule-reboot')

    # --- start listener (loopback only) ----------------------------------------
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://127.0.0.1:$Port/")
    # The Set Credentials smartcard picker (Get-Credential) must run on this single
    # accept thread (it needs the console host to render), so it BLOCKS the loop until
    # the operator finishes. From http.sys's view the in-flight POST /api/cred
    # connection is then "idle" (no bytes flowing), and the default IdleConnection
    # timeout (~2 min) can drop it mid-pick -> the page shows "Credential set failed:
    # network error". Extend it so a deliberate, operator-present ADW/PIN pick has
    # room to complete. (Loopback, single operator - a long idle timeout is harmless.)
    try { $listener.TimeoutManager.IdleConnection = [TimeSpan]::FromMinutes(20) } catch {}
    try {
        $listener.Start()
    } catch [System.Net.HttpListenerException] {
        Write-Host ""
        Write-Host "  Could not bind http://127.0.0.1:$Port/ : $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  Fix (pick one):" -ForegroundColor Yellow
        Write-Host "    - Run this from an ELEVATED PowerShell (the same way you run admin tools), OR" -ForegroundColor Yellow
        Write-Host "    - One-time URL reservation (needs admin once):" -ForegroundColor Yellow
        Write-Host "        netsh http add urlacl url=http://127.0.0.1:$Port/ user=$env:USERDOMAIN\$env:USERNAME" -ForegroundColor Cyan
        Write-Host "    - Or try a different port:  ""Launch JANET Web.cmd"" -Port 8090" -ForegroundColor Yellow
        return
    }
    Write-Host "  Listening. Ctrl+C to stop." -ForegroundColor DarkGray


    $pendingAccept = $null
    try {
        while ($listener.IsListening) {
            # Live usage snapshots: every accept-loop pass (each request AND each 2 s
            # heartbeat tick) offer the logging bridge a chance to flush cumulative
            # per-tool usage rows (RowType='Snapshot', ~5 min cadence, only when new
            # activity was tallied). Without this the dashboard sees NOTHING until a
            # clean server stop - and nothing EVER if the console is killed.
            try { Write-JanetWebUsageSnapshot -Context $state.LogCtx } catch {}
            # Same cheap-hook shape for the armed restart: every pass (request or
            # 2 s heartbeat) the tick decides whether the one armed wave should
            # fire, expire, or keep waiting. No timer, no poller, no thread - and
            # a 2 s heartbeat is plenty of resolution for a minute-granularity
            # reboot time. NEVER THROWS (it owns its own try/catch).
            & $tickArmedRestart
            # Heartbeat accept: one async accept stays armed; wait in 2 s slices so
            # Ctrl+C is honored promptly and the reaper runs even when no client is
            # polling. Requests are still handled strictly on this one thread.
            if (-not $pendingAccept) {
                try { $pendingAccept = $listener.BeginGetContext($null, $null) } catch { break }
            }
            if (-not $pendingAccept.AsyncWaitHandle.WaitOne(2000)) {
                & $reapJobs ''   # maintenance tick
                continue
            }
            $ctx = $null
            try { $ctx = $listener.EndGetContext($pendingAccept) } catch { break } finally { $pendingAccept = $null }  # Stop() faults the pending accept -> same exit as the old blocked GetContext
            try { $pendingAccept = $listener.BeginGetContext($null, $null) } catch {}   # re-arm before dispatch; a failure here is retried (or breaks) at the top of the loop
            try {
                $req  = $ctx.Request
                $resp = $ctx.Response
                $path = $req.Url.AbsolutePath
                $verb = $req.HttpMethod

                # ---- Host-header guard (loop-4, roadmap item 3) ----
                # http.sys routes an IP-LITERAL prefix by destination ip:port, NOT by
                # the Host string - a live probe (loop 4) showed 'Host: evil.example.com'
                # reaching this loop and being served 200. A DNS-rebound page (attacker
                # hostname re-resolving to 127.0.0.1) is same-origin to its own name,
                # letting it read responses from the no-token surfaces (static UI,
                # report-preview). Fail closed: serve only the two names a legitimate
                # local browser can send; anything else - including a missing Host -
                # gets 421 Misdirected and no content. (-ne is case-insensitive in PS,
                # which matches hostname semantics.)
                # ASSUMES a non-default port: the launcher binds 8089..8100, so the
                # browser always sends Host WITH the port. If the listener were ever
                # bound to 80/443 the browser would omit the port and this guard would
                # 421 the UI itself - keep the bind off the scheme-default ports.
                $hostHdr = [string]$req.Headers['Host']
                if ($hostHdr -ne "127.0.0.1:$Port" -and $hostHdr -ne "localhost:$Port") {
                    & $writeBytes $resp ([System.Text.Encoding]::UTF8.GetBytes('misdirected (bad Host header)')) 421 'text/plain'
                    continue
                }

                # ---- static assets (no token; UI code only) ----
                # Path-traversal defense + dev/underscore-asset 404 live in the extracted,
                # unit-tested Get-JanetWebAssetPath (loop13). $null -> 404; a real in-root
                # leaf -> served. (audit#28 underscore rule folded into the helper.)
                if ($path -notlike '/api/*') {
                    $asset = Get-JanetWebAssetPath -WebDir $webDir -UrlPath $path
                    if ($asset) {
                        # audit 2026-07-23: conditional GET. Send Last-Modified with every 200
                        # and honor If-Modified-Since with a bodyless 304 so warm reloads skip
                        # the disk read + full-body send. Compare at WHOLE-SECOND granularity
                        # (HTTP dates carry no sub-second part, so an untruncated mtime would
                        # never match). Deliberately minimal - no ETag machinery.
                        $assetType = & $contentType ([System.IO.Path]::GetExtension($asset))
                        $mtime = [System.IO.File]::GetLastWriteTimeUtc($asset)
                        $mtime = $mtime.AddTicks(-($mtime.Ticks % [TimeSpan]::TicksPerSecond))
                        try { $resp.Headers['Last-Modified'] = $mtime.ToString('r') } catch {}
                        # audit 2026-07-24 (P2): Last-Modified WITHOUT Cache-Control licenses
                        # the browser's heuristic freshness rule (~10% of the file's age), so
                        # after a version bump an operator kept getting STALE js/css out of
                        # cache against fresh HTML - a half-updated UI that is near-impossible
                        # to diagnose from the field. 'no-cache' does NOT forbid caching: it
                        # forbids serving from cache WITHOUT revalidating, so the stored copy
                        # plus If-Modified-Since still produces the bodyless 304 below on every
                        # warm reload. We're on loopback, so a mandatory revalidation round-trip
                        # is free and correctness wins over cache efficiency.
                        try { $resp.Headers['Cache-Control'] = 'no-cache' } catch {}
                        $ims = [datetime]::MinValue
                        $imsOk = [datetime]::TryParse([string]$req.Headers['If-Modified-Since'], [System.Globalization.CultureInfo]::InvariantCulture, ([System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal), [ref]$ims)
                        if ($imsOk -and $ims -ge $mtime) {
                            & $writeBytes $resp ([byte[]]@()) 304 $assetType
                        } else {
                            & $writeBytes $resp ([System.IO.File]::ReadAllBytes($asset)) 200 $assetType
                        }
                    } else {
                        & $writeBytes $resp ([System.Text.Encoding]::UTF8.GetBytes('not found')) 404 'text/plain'
                    }
                    continue
                }

                # GET /api/report-preview?id=<id> -> serve a stashed report ONCE.
                # NO session-token check (placed BEFORE the token gate on purpose): a
                # top-level window.open() navigation cannot send the X-Janet-Token
                # header, so the one-shot unguessable GUID id - minted by the
                # authenticated POST below, 5-min TTL, deleted on read - IS the
                # capability. Served with its OWN response + a relaxed 'unsafe-inline'
                # script-src so the generated report's inline <script> (the Dirty 30
                # pill filters / live search) runs; a data: URI would inherit the SPA's
                # strict script-src (CSP3 policy-container inheritance) and stay dead.
                # The CSP 'sandbox allow-scripts' directive (loop-3, roadmap item 2) is
                # the XSS backstop: the document gets an OPAQUE origin, so even if an
                # unescaped report field ever smuggled a hostile <script> past
                # ConvertTo-HtmlEscaped, it cannot read the SPA's sessionStorage token
                # (opaque origin -> storage access throws) and cannot call /api
                # same-origin. The report's own inline script is pure-DOM (pill
                # filters/search) and runs fine under allow-scripts. Deliberately NO
                # allow-same-origin - adding it would delete the entire backstop.
                if ($verb -eq 'GET' -and $path -eq '/api/report-preview') {
                    $rid = [string]$req.QueryString['id']
                    $rp = $null; if (-not [string]::IsNullOrWhiteSpace($rid)) { $rp = $state.ReportPreviews[$rid] }
                    if ($rp) { [void]$state.ReportPreviews.Remove($rid) }
                    $reportCsp = "sandbox allow-scripts; default-src 'self'; script-src 'unsafe-inline' 'self'; style-src 'unsafe-inline' 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'"
                    $body = if ($rp) { [string]$rp.Html } else { '<!doctype html><meta charset="utf-8"><title>Report preview</title><body style="font-family:Segoe UI,sans-serif;background:#08080C;color:#c8c8d0;padding:28px">This report preview has expired or was already opened. Re-open it from the Reports tool.</body>' }
                    & $writeBytes $resp ([System.Text.Encoding]::UTF8.GetBytes($body)) 200 'text/html; charset=utf-8' $reportCsp
                    continue
                }

                # ---- /api/* : enforce the per-launch session token (constant-time) ----
                # The query-string token (?t=) is honoured ONLY on the unload beacon-cancel
                # route: navigator.sendBeacon (POST /api/job/<id>/cancel, fired on pagehide)
                # cannot set the X-Janet-Token header, so ?t= is its sole carrier there. Every
                # other /api/* route must present the header token, so a bare URL carrying ?t=
                # (referer leak, shared link, browser history) can't drive the tool/action
                # surface. The bootstrap page load is a static (non-/api/) route and the SPA
                # strips ?t= after first paint, so no /api/* GET ever needs it.
                $tok = $req.Headers['X-Janet-Token']
                if ([string]::IsNullOrEmpty($tok) -and $verb -eq 'POST' -and $path -match '^/api/job/[^/]+/cancel$') { $tok = $req.QueryString['t'] }
                $tokenOk = $false
                if ($tok -and $tok.Length -eq $Token.Length) {
                    $d = 0; for ($ti = 0; $ti -lt $Token.Length; $ti++) { $d = $d -bor ([int][char]$tok[$ti] -bxor [int][char]$Token[$ti]) }
                    $tokenOk = ($d -eq 0)
                }
                if (-not $tokenOk) { & $writeJson $resp @{ error = 'forbidden (bad or missing session token)' } 403; continue }

                $seg = $path.Trim('/').Split('/')   # e.g. api tool <id> action <actionId>

                # GET /api/tools
                if ($verb -eq 'GET' -and $path -eq '/api/tools') {
                    $tools = foreach ($t in $state.Registry.tools) {
                        $m = $state.Manifests[$t.id]
                        $acts = @(); $ver = '1.0.0'
                        if ($m) { $acts = $m.actions; if ($m.version) { $ver = [string]$m.version } }
                        @{ id=$t.id; name=$t.name; category=$t.category; icon=$t.icon; summary=$t.summary; version=$ver; beta=[bool]$t.beta; actions=$acts }
                    }
                    & $writeJson $resp @{ suite = $state.Registry.suite; tools = @($tools) }
                    continue
                }

                # /api/cred
                if ($path -eq '/api/cred') {
                    if ($verb -eq 'GET')    { & $writeJson $resp (Get-JanetWebCredentialStatus -Credential $state.Cred); continue }
                    if ($verb -eq 'POST')   { $r = Prompt-JanetWebCredential; if ($r.ok) { $state.Cred = $r.cred }; & $writeJson $resp @{ ok=$r.ok; message=$r.message; status=(Get-JanetWebCredentialStatus -Credential $state.Cred) }; continue }
                    # DELETE also drops the responsibility ack: the ack was given FOR the
                    # credential being cleared. Without this, ack + clear-cred + later
                    # re-POST /cred re-armed the destructive gate with no fresh ack
                    # (AckGiven was a one-time-per-process flag).
                    # Clearing the credential HARD-EXPIRES any armed restart: the wave was
                    # armed against that credential and that ack. (The tick would refuse it
                    # anyway - $state.Cred is null - but drop it HERE so the UI sees the arm
                    # disappear the instant the operator disarms, not up to 2 s later.)
                    if ($verb -eq 'DELETE') { $state.Cred = $null; $state.AckGiven = $false;
                        if ($state.ArmedRestart) {
                            $state.ArmedRestart.Status = 'expired'
                            $state.ArmedRestart.Reason = 'the credential was cleared after the wave was armed'
                            $state.LastFiredArm = $state.ArmedRestart; $state.ArmedRestart = $null
                            try { Write-Host '  [armed restart] EXPIRED - NOT fired: the credential was cleared.' -ForegroundColor Yellow } catch {}
                        }
                        & $writeJson $resp @{ ok=$true; status=(Get-JanetWebCredentialStatus -Credential $null) }; continue
                    }
                }

                # POST /api/session/start -> record the responsibility acknowledgment.
                # The destructive-action gate (below, in the action dispatch) requires
                # BOTH this ack AND a set credential, so the read-only AD-search bypass
                # (which never calls this) can never reach a state-changing action. The
                # browser gate mirrors this; this server flag is the authoritative check.
                if ($verb -eq 'POST' -and $path -eq '/api/session/start') {
                    $ack = $false
                    if ($req.HasEntityBody) { try { $b = & $readBody $req 4096; if ($b) { $o = ConvertFrom-Json $b; if ($o.ack -eq $true -or "$($o.ack)" -eq 'yes') { $ack = $true } } } catch {} }
                    if ($ack) { $state.AckGiven = $true }
                    & $writeJson $resp @{ ok=$true; ack=[bool]$state.AckGiven; credSet=($null -ne $state.Cred); active=($state.AckGiven -and $null -ne $state.Cred) }
                    continue
                }

                # GET /api/status -> session + logging-health surface (drives the
                # 'logging is local-only' banner + the Logs viewer path).
                if ($verb -eq 'GET' -and $path -eq '/api/status') {
                    $lc = $state.LogCtx
                    $logRoot = if ($lc.OnShare) { $lc.NetRoot } else { $lc.JanetLocal }
                    & $writeJson $resp @{
                        sessionId = $lc.SessionId; operator = $lc.Operator; asi = $lc.Asi
                        onShare = [bool]$lc.OnShare; localOnly = (-not [bool]$lc.OnShare)
                        shareWarning = [string]$lc.ShareWarning; logRoot = [string]$logRoot
                        hostsTouched = $lc.Hosts.Count; vulnsPatched = $lc.Vulns; failures = $lc.Failures
                        runCount = $lc.RunCount; runSuccess = $lc.RunSuccess; runFailed = $lc.RunFailed
                        log4jStaging = [string](Join-Path (Join-Path $packagesDir 'Log4j') 'NewFiles'); packagesRoot = [string]$packagesDir
                    }
                    continue
                }

                # GET /api/target-groups -> the TargetManager saved-groups map
                # (name -> host text), {} when nothing has been saved yet. Read as
                # raw JSON pass-through (validated) so key order/shape is preserved.
                if ($verb -eq 'GET' -and $path -eq '/api/target-groups') {
                    $tgJson = '{}'
                    try {
                        if (Test-Path -LiteralPath $targetGroupsFile) {
                            $tgRaw = Get-Content -LiteralPath $targetGroupsFile -Raw -Encoding UTF8 -ErrorAction Stop
                            if (-not [string]::IsNullOrWhiteSpace($tgRaw)) {
                                # A corrupt/partial file must not poison the UI - fall back to {}.
                                try { [void](ConvertFrom-Json $tgRaw); $tgJson = $tgRaw } catch { $tgJson = '{}' }
                            }
                        }
                    } catch {}
                    & $writeBytes $resp ([System.Text.Encoding]::UTF8.GetBytes($tgJson)) 200 'application/json; charset=utf-8'
                    continue
                }

                # POST /api/target-groups -> persist the whole saved-groups map. Body
                # IS the JSON object (last-writer-wins, like the KEV catalog); size-
                # capped and written atomically (temp + swap) so the live file is never
                # half-written and a bad body can't corrupt it.
                if ($verb -eq 'POST' -and $path -eq '/api/target-groups') {
                    if ($req.ContentLength64 -gt 1048576) { & $writeJson $resp @{ error='target groups too large (1 MB cap)' } 413; continue }
                    $raw = ''
                    if ($req.HasEntityBody) {
                        try { $raw = & $readBody $req 1048576 } catch { & $writeJson $resp @{ error = $_.Exception.Message } 413; continue }
                    }
                    if ([string]::IsNullOrWhiteSpace($raw)) { $raw = '{}' }
                    # Must parse as JSON (the store only ever sends an object map); reject
                    # anything malformed rather than write garbage to the saved file.
                    try { [void](ConvertFrom-Json $raw) } catch { & $writeJson $resp @{ error='invalid JSON body' } 400; continue }
                    try {
                        $tgDir = Split-Path -Parent $targetGroupsFile
                        if (-not (Test-Path -LiteralPath $tgDir)) { New-Item -ItemType Directory -Path $tgDir -Force -ErrorAction Stop | Out-Null }
                        $tgTmp = Join-Path $tgDir ("target-groups.$PID.$([DateTime]::UtcNow.Ticks).tmp")
                        $enc = New-Object System.Text.UTF8Encoding($false)
                        [System.IO.File]::WriteAllText($tgTmp, $raw, $enc)
                        try {
                            if (Test-Path -LiteralPath $targetGroupsFile) {
                                # PS 5.1 has no File.Move overwrite overload; File.Replace is a true
                                # atomic swap. NullString (not $null) binds the no-backup overload.
                                try { [System.IO.File]::Replace($tgTmp, $targetGroupsFile, [NullString]::Value) }
                                catch { Move-Item -LiteralPath $tgTmp -Destination $targetGroupsFile -Force }   # DFS / odd-SMB fallback
                            } else {
                                Move-Item -LiteralPath $tgTmp -Destination $targetGroupsFile -Force
                            }
                        } catch {
                            Remove-Item -LiteralPath $tgTmp -Force -ErrorAction SilentlyContinue
                            throw
                        }
                        & $writeJson $resp @{ ok=$true }
                    } catch {
                        $ex = $_
                        try { Write-Host ("  [500] target-groups -> $($ex.Exception.Message)") -ForegroundColor Red } catch {}
                        & $writeJson $resp @{ ok=$false; error='internal error - see server console' } 500
                    }
                    continue
                }

                # POST /api/session/end -> capture operator closing notes + ASI/RFC.
                # Notes/ASI ride to the SessionEnd usage rollup at shutdown; a
                # SessionNotes row is also written to the Runs CSV now (faithful to
                # the desktop closing-notes dialog) so notes survive an unclean stop.
                if ($verb -eq 'POST' -and $path -eq '/api/session/end') {
                    $notes = ''; $asi = $null
                    if ($req.ContentLength64 -le 1048576 -and $req.HasEntityBody) {
                        $raw = ''; try { $raw = & $readBody $req 1048576 } catch {}
                        if ($raw) { try { $b = ConvertFrom-Json $raw; if ($null -ne $b.notes) { $notes = [string]$b.notes }; if ($null -ne $b.asi) { $asi = [string]$b.asi } } catch {} }
                    }
                    if ($null -ne $asi) { $state.LogCtx.Asi = $asi }
                    $state.ClosingNotes = $notes
                    # Re-ping-gate the share before the Runs CSV write: it can die
                    # mid-session and this append runs on the accept thread. Notes
                    # still reach the shutdown rollup via ClosingNotes if skipped.
                    $shareOk = if ($state.LogCtx.OnShare) { Test-JanetWebShare -Root ([string]$state.LogCtx.NetRoot) } else { $true }
                    if ($shareOk) {
                        try { Write-JanetWebRun -Context $state.LogCtx -Tool 'acas' -RowType 'SessionNotes' -Action 'SessionEnd' -Notes $notes -HostsTotal $state.LogCtx.Hosts.Count -Success $state.LogCtx.RunSuccess -Failed $state.LogCtx.RunFailed } catch {}
                    }
                    # End Session DISARMS server-side: drop the ack AND the credential so
                    # the destructive gate ($state.AckGiven -and $state.Cred) goes cold.
                    # Formerly this handler only recorded notes - the gate stayed armed
                    # for the life of the process after "End Session", and the operator's
                    # "I locked it" signal was false. Re-arming requires a fresh POST
                    # /api/cred + POST /api/session/start ack.
                    $state.AckGiven = $false
                    $state.Cred = $null
                    # ...and HARD-EXPIRES any armed restart with it. "End Session" must
                    # mean the box is quiet: an armed wave that outlived the session that
                    # armed it would be exactly the unattended execution this design
                    # refuses to create. The tick would refuse it on the next pass anyway
                    # (fail-closed in two places); this makes it immediate and visible.
                    if ($state.ArmedRestart) {
                        $state.ArmedRestart.Status = 'expired'
                        $state.ArmedRestart.Reason = 'the operator ended the admin session after the wave was armed'
                        $state.LastFiredArm = $state.ArmedRestart; $state.ArmedRestart = $null
                        try { Write-Host '  [armed restart] EXPIRED - NOT fired: the admin session was ended.' -ForegroundColor Yellow } catch {}
                        try { Write-JanetWebSessionLog -Context $state.LogCtx -Tool 'restart' -Action 'ARM:expired' -Target '(armed dispatch)' -Result 'Expired' -Detail 'the operator ended the admin session after the wave was armed' } catch {}
                    }
                    & $writeJson $resp @{ ok=$true; disarmed=$true; hostsTouched=$state.LogCtx.Hosts.Count; vulnsPatched=$state.LogCtx.Vulns; runCount=$state.LogCtx.RunCount; failures=$state.LogCtx.Failures }
                    continue
                }

                # GET /api/logs/tail?tool=<id>&n=<rows> -> the last N rows of this
                # operator's current-month detail CSV for the tool, so the Logs viewer
                # can show recent audit activity without an Open-Folder analog.
                if ($verb -eq 'GET' -and $path -eq '/api/logs/tail') {
                    $lc = $state.LogCtx
                    $toolId = [string]$req.QueryString['tool']; if ([string]::IsNullOrWhiteSpace($toolId)) { $toolId = 'acas' }
                    # audit#21: TryParse writes 0 into [ref]$n on a missing/bad value,
                    # clobbering the default; only accept a successful parse.
                    $n = 200; $parsedN = 0; if ([int]::TryParse([string]$req.QueryString['n'], [ref]$parsedN)) { $n = $parsedN }
                    if ($n -lt 1) { $n = 1 } elseif ($n -gt 2000) { $n = 2000 }
                    $toolName = Resolve-JanetWebToolName -ToolId $toolId
                    $root = if ($lc.OnShare) { $lc.NetRoot } else { $lc.JanetLocal }
                    $file = Join-Path (Join-Path (Join-Path $root $toolName) $lc.UserFolder) "$($lc.Month)_detail.csv"
                    $header = ''; $rows = @(); $exists = $false
                    # Ping-gate a share-hosted CSV first (CACHED host probe, audit
                    # 2026-07-23 - the uncached 1.5s TCP probe ran per poll, so a dead
                    # log share stalled every request), and tail it instead of
                    # full-reading: this runs on the single-threaded accept loop.
                    $tailOk = Test-JanetWebPathReachable $file
                    # audit 2026-07-28: this was the ONE consumer reading the month CSV by
                    # EXACT name. When the live file's header does not match the current
                    # schema AND the rename to .legacy_<stamp> fails (a desktop tool holding
                    # an append handle on the same shared monthly CSV defeats the two
                    # no-backoff retries), Invoke-JanetWebHeaderEnsure redirects every row to
                    # a sister '<base>.r<stamp>.csv'. reports.psm1 and history.psm1 were both
                    # taught to glob '<month>_detail*.csv' for exactly this reason; the tail
                    # endpoint was missed, so the viewer showed a stale header and stale rows
                    # with exists=true - healthy-looking and wrong. Pick the newest
                    # non-legacy sibling. The reachability gate stays AHEAD of the
                    # enumeration: this runs on the single-threaded accept loop and must not
                    # touch a dead share.
                    if ($tailOk) {
                        try {
                            $tailDir = Join-Path (Join-Path $root $toolName) $lc.UserFolder
                            $cand = @(Get-ChildItem -LiteralPath $tailDir -Filter "$($lc.Month)_detail*.csv" -File -ErrorAction Stop |
                                      Where-Object { $_.Name -notlike '*.legacy_*' } | Sort-Object LastWriteTime -Descending)
                            if ($cand.Count) { $file = $cand[0].FullName }
                        } catch {}
                    }
                    if ($tailOk -and (Test-Path -LiteralPath $file)) {
                        $exists = $true
                        try {
                            $header = [string](Get-Content -LiteralPath $file -TotalCount 1 -Encoding UTF8 -ErrorAction Stop)
                            $rows = @(Get-Content -LiteralPath $file -Tail $n -Encoding UTF8 -ErrorAction Stop | Where-Object { $_ -ne '' -and $_ -ne $header })
                        } catch {}
                    }
                    & $writeJson $resp @{ ok=$true; path=$file; exists=$exists; onShare=[bool]$lc.OnShare; header=$header; rows=@($rows) }
                    continue
                }

                # GET /api/logs/transcript?tool=<id>&n=<lines> -> this session's per-tool .log
                # NARRATIVE (the human-readable transcript), for the in-UI viewer's Transcript tab.
                if ($verb -eq 'GET' -and $path -eq '/api/logs/transcript') {
                    $lc = $state.LogCtx
                    $toolId = [string]$req.QueryString['tool']; if ([string]::IsNullOrWhiteSpace($toolId)) { $toolId = 'acas' }
                    $n = 800; $parsedN = 0; if ([int]::TryParse([string]$req.QueryString['n'], [ref]$parsedN)) { $n = $parsedN }  # audit#21
                    if ($n -lt 1) { $n = 1 } elseif ($n -gt 5000) { $n = 5000 }
                    $tgt  = Get-JanetWebSessionLogTarget -Context $lc -Tool $toolId
                    $file = if ($lc.OnShare) { $tgt.Net } else { $tgt.Local }
                    $exists = $false; $lines = @()
                    $tailOk = Test-JanetWebPathReachable $file   # audit 2026-07-23: cached probe (see /logs/tail)
                    if ($tailOk -and (Test-Path -LiteralPath $file)) {
                        $exists = $true
                        try { $lines = @(Get-Content -LiteralPath $file -Tail $n -Encoding UTF8 -ErrorAction Stop) } catch {}
                    }
                    & $writeJson $resp @{ ok=$true; path=$file; exists=$exists; onShare=[bool]$lc.OnShare; lines=@($lines) }
                    continue
                }

                # POST /api/upload -> browser-native file upload. The raw request
                # body IS the file bytes; the original name rides in the
                # X-Janet-Filename header (URL-encoded). We stream-copy to a fresh
                # temp file and hand back its server path, so every path-based tool
                # engine works unchanged. Binary-safe (MSU, xlsx, etc.).
                if ($verb -eq 'POST' -and $path -eq '/api/upload') {
                    $maxUpload = 1073741824L   # 1 GB ceiling (real MSU/xlsx/CSV are well under this)
                    if ($req.ContentLength64 -gt $maxUpload) {
                        & $writeJson $resp @{ ok=$false; error="upload too large ($([int]($req.ContentLength64/1MB)) MB exceeds the 1024 MB cap)" } 413
                        continue
                    }
                    # Filename + optional co-location subdir are operator-controlled headers;
                    # sanitize both to traversal-free, device-safe names via the extracted,
                    # unit-tested helpers (loop14 - write-path twin of Get-JanetWebAssetPath).
                    $fname = Get-JanetWebSafeUploadName $req.Headers['X-Janet-Filename']
                    $subInfo = Get-JanetWebSafeUploadSubdir $req.Headers['X-Janet-Subdir']
                    $subName = $subInfo.Name; $subShared = $subInfo.Shared
                    $sub  = Join-Path $uploadsDir $subName
                    $dest = $null
                    try {
                        New-Item -ItemType Directory -Path $sub -Force -ErrorAction Stop | Out-Null
                        $dest = Join-Path $sub $fname
                        $fs = [System.IO.File]::Create($dest)
                        try {
                            if ($req.HasEntityBody) {
                                # Bounded copy: abort+delete if the stream runs past the cap
                                # (covers chunked uploads / a lying Content-Length).
                                $buf = New-Object byte[] 81920
                                $total = 0L
                                while (($read = $req.InputStream.Read($buf, 0, $buf.Length)) -gt 0) {
                                    $total += $read
                                    if ($total -gt $maxUpload) { throw 'upload exceeded the 1024 MB cap' }
                                    $fs.Write($buf, 0, $read)
                                }
                            }
                        } finally { $fs.Close() }
                        & $writeJson $resp @{ ok = $true; path = $dest; name = $fname }
                    } catch {
                        $ex = $_
                        try { if ($dest -and (Test-Path -LiteralPath $dest)) { Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue } } catch {}
                        # Drop the per-upload guid subdir so a failed upload leaves no empty
                        # temp dir - but NOT a shared (X-Janet-Subdir) dir, which may already
                        # hold sibling files from a prior successful upload in the same group.
                        try { if (-not $subShared -and $sub -and (Test-Path -LiteralPath $sub)) { Remove-Item -LiteralPath $sub -Recurse -Force -ErrorAction SilentlyContinue } } catch {}
                        try { Write-Host ("  [500] upload -> $($ex.Exception.Message)`r`n$($ex.ScriptStackTrace)") -ForegroundColor Red } catch {}
                        & $writeJson $resp @{ ok = $false; error = 'internal error - see server console' } 500
                    }
                    continue
                }

                # POST /api/report-preview -> stash generated report HTML for a
                # one-shot popup preview; returns { id }. This POST is token-gated
                # (fetched via ctx.api); the paired GET /api/report-preview?id= (above,
                # pre-token) then serves it to a window.open() popup with its own
                # relaxed CSP. Needed because the report's inline <script> cannot run
                # under a data: URI (it inherits the SPA's strict script-src hash).
                if ($verb -eq 'POST' -and $path -eq '/api/report-preview') {
                    if ($req.ContentLength64 -gt 26214400) { & $writeJson $resp @{ error='report too large (25 MB cap)' } 413; continue }
                    $html = ''
                    if ($req.HasEntityBody) {
                        $raw = ''
                        try { $raw = & $readBody $req 26214400 } catch { & $writeJson $resp @{ error = $_.Exception.Message } 413; continue }
                        if ($raw) { try { $o = ConvertFrom-Json $raw; if ($null -ne $o.html) { $html = [string]$o.html } } catch { $html = [string]$raw } }
                    }
                    # Evict stale stashes (>5 min) so a long session can't accumulate
                    # report bodies; then mint an unguessable one-shot id.
                    foreach ($rk in @($state.ReportPreviews.Keys)) {
                        $rpOld = $state.ReportPreviews[$rk]
                        if ($rpOld -and ((Get-Date) - $rpOld.At).TotalMinutes -gt 5) { [void]$state.ReportPreviews.Remove($rk) }
                    }
                    $rid = New-JanetWebSecureToken   # loop34: explicit CSPRNG (was [guid]::NewGuid())
                    $state.ReportPreviews[$rid] = @{ Html = $html; At = (Get-Date) }
                    & $writeJson $resp @{ ok=$true; id=$rid }
                    continue
                }

                # GET /api/tool/pkginstall/packages?kind=psadt|msi -> list deployable
                # packages found under the packages root (the dropdown source). Server
                # owns the enumeration (no module import) so it's fast + always current.
                if ($verb -eq 'GET' -and $path -eq '/api/tool/pkginstall/packages') {
                    $kind = [string]$req.QueryString['kind']; if (@('psadt','msi') -notcontains $kind) { $kind = 'psadt' }
                    $pkgs = New-Object System.Collections.ArrayList
                    # Ping-gate a UNC packages root (the work share) first, mirroring /msis:
                    # a dead share must not hang the accept loop on the recursive enumeration.
                    # audit 2026-07-23: cached probe helper (was an uncached 1.5s TCP hit per call).
                    $pkgRootOk = Test-JanetWebPathReachable $packagesDir
                    if ($pkgRootOk -and (Test-Path -LiteralPath $packagesDir)) {
                        foreach ($d in (Get-ChildItem -LiteralPath $packagesDir -Directory -ErrorAction SilentlyContinue | Sort-Object Name)) {
                            $hasPsadt = $false; $msiCount = 0
                            # PSADT v3 entry = Deploy-Application.ps1; v4 renamed it Invoke-AppDeployToolkit.ps1
                            foreach ($psadtName in @('Deploy-Application.ps1','Invoke-AppDeployToolkit.ps1')) {
                                try { if (Get-ChildItem -LiteralPath $d.FullName -Filter $psadtName -Recurse -Depth 4 -File -ErrorAction SilentlyContinue | Select-Object -First 1) { $hasPsadt = $true; break } } catch {}
                            }
                            # Only the MSI dropdown needs the (more expensive) *.msi scan; and
                            # a PSADT bundle is never an MSI candidate, so skip it once found.
                            if ($kind -eq 'msi' -and -not $hasPsadt) {
                                try { $msiCount = @(Get-ChildItem -LiteralPath $d.FullName -Filter '*.msi' -Recurse -Depth 4 -File -ErrorAction SilentlyContinue).Count } catch {}
                            }
                            $match = if ($kind -eq 'psadt') { $hasPsadt } else { ($msiCount -gt 0) -and -not $hasPsadt }
                            if ($match) {
                                $detail = if ($kind -eq 'psadt') { 'PSADT' } else { "$msiCount MSI(s)" }
                                [void]$pkgs.Add(@{ name=$d.Name; path=$d.FullName; detail=$detail })
                            }
                        }
                    }
                    & $writeJson $resp @{ root=$packagesDir; kind=$kind; packages=@($pkgs) }
                    continue
                }

                # GET /api/tool/pkginstall/msis?path=<bundle> -> the .msi files inside a
                # bundle folder (relative paths), so the UI can show them as checkboxes
                # instead of making the operator type relative paths.
                if ($verb -eq 'GET' -and $path -eq '/api/tool/pkginstall/msis') {
                    $bp = [string]$req.QueryString['path']
                    $msis = New-Object System.Collections.ArrayList
                    # Arbitrary operator path BY DESIGN (audit 2026-07-23): this listing is
                    # token-gated and read-only (returns .msi names only), and the tool must
                    # deploy from wherever the operator staged a bundle (local disk, any
                    # reachable share) - so the path is deliberately NOT confined to the
                    # packages root. Ping-gate a UNC host (cached probe helper, same audit)
                    # so a dead share can't hang the accept loop on Test-Path/enumeration.
                    $bpOk = Test-JanetWebPathReachable $bp
                    if ($bpOk -and $bp -and ($bp -like '*.msi') -and (Test-Path -LiteralPath $bp -PathType Leaf)) {
                        # Direct .msi file path: the file IS the bundle - one relative leaf.
                        [void]$msis.Add((Split-Path -Leaf $bp))
                    } elseif ($bpOk -and $bp -and (Test-Path -LiteralPath $bp -PathType Container)) {
                        try {
                            $base = (Resolve-Path -LiteralPath $bp).Path.TrimEnd('\','/')
                            foreach ($m in (Get-ChildItem -LiteralPath $bp -Filter '*.msi' -Recurse -Depth 4 -File -ErrorAction SilentlyContinue | Sort-Object FullName | Select-Object -First 500)) {
                                $rel = $m.FullName.Substring($base.Length).TrimStart('\','/')
                                [void]$msis.Add($rel)
                            }
                        } catch {}
                    }
                    & $writeJson $resp @{ path=$bp; msis=@($msis) }
                    continue
                }

                # GET /api/tool/<id>/manifest
                if ($verb -eq 'GET' -and $seg.Count -eq 4 -and $seg[1] -eq 'tool' -and $seg[3] -eq 'manifest') {
                    $m = $state.Manifests[$seg[2]]
                    if ($m) { & $writeJson $resp $m } else { & $writeJson $resp @{ error = 'tool manifest unavailable' } 404 }
                    continue
                }

                # GET /api/jobs -> every job this server still knows about, plus the
                # armed restart (if any) and the server's clock.
                #
                # This is the REATTACH surface. Before it, a browser reload lost all
                # sight of work the server was still doing: run-state lived only in the
                # page. Now a reloaded (or second) tab can see that a wave is still
                # running and re-attach to its event stream, and an armed wave is
                # visible in the shell strip instead of hiding inside a browser timer.
                # STRICTLY read-only: it starts nothing, resumes nothing, and returns
                # no parameters - the reattach UI offers status + Cancel, never a
                # re-run. Same token gate as every other /api route (it sits after it).
                if ($verb -eq 'GET' -and $path -eq '/api/jobs') {
                    & $reapJobs ''
                    $jobList = New-Object System.Collections.ArrayList
                    foreach ($jk in @($state.Jobs.Keys | Sort-Object)) {
                        $jj = $state.Jobs[$jk]
                        if (-not $jj) { continue }
                        [void]$jobList.Add(@{
                            jobId      = [string]$jj.Id
                            tool       = [string]$jj.Tool
                            action     = [string]$jj.Action
                            status     = [string]$jj.Status
                            startedAt  = $(if ($jj.StartedAt)  { ([datetime]$jj.StartedAt).ToString('o') }  else { $null })
                            finishedAt = $(if ($jj.FinishedAt) { ([datetime]$jj.FinishedAt).ToString('o') } else { $null })
                        })
                    }
                    & $writeJson $resp @{ jobs = @($jobList); armed = (& $armSummary $state.ArmedRestart); now = (Get-Date).ToString('o') }
                    continue
                }

                # POST /api/armed-restart/disarm -> stand down the armed wave.
                # An armed restart must be cancellable AT ANY TIME, from any tab, with
                # no ceremony: this is that. Idempotent (disarmed=false when nothing
                # was armed) so a double-click or a stale tab can't error.
                if ($verb -eq 'POST' -and $path -eq '/api/armed-restart/disarm') {
                    $oldArm = $state.ArmedRestart
                    $state.ArmedRestart = $null
                    if ($oldArm) {
                        $oldArm.Status = 'disarmed'
                        $state.LastFiredArm = $oldArm
                        try { Write-Host ("  [armed restart] DISARMED by the operator - $([int]$oldArm.HostCount) host(s) will NOT be restarted.") -ForegroundColor Yellow } catch {}
                        try { Write-JanetWebSessionLog -Context $state.LogCtx -Tool 'restart' -Action 'ARM:disarmed' -Target "(armed dispatch - $([int]$oldArm.HostCount) host(s))" -Result 'Disarmed' -Detail 'operator stood the armed wave down before it fired' } catch {}
                    }
                    & $writeJson $resp @{ ok = $true; disarmed = [bool]$oldArm }
                    continue
                }

                # POST /api/tool/restart/action/arm-dispatch -> hold a FULLY CONFIRMED
                # dispatch-restart param set in memory and fire it at the scheduled time.
                #
                # This route exists because the delayed start used to be a browser
                # setInterval (restart.view.js): a stray F5 silently lost a 2 AM reboot
                # wave, and the tooltip had to say "Leave the tool open". The countdown
                # moves to the server, which must stay up for the wave anyway.
                #
                # NOTHING IS WEAKENED - the gate moves EARLIER:
                #   * the admin-session gate (ack + credential) is enforced HERE, at arm
                #     time, exactly as the dispatch route enforces it;
                #   * the typed RESTART word is demanded HERE by Test-JanetWebArmRequest
                #     (live only, dry-run exempt - identical to the engine's rule) and it
                #     stays inside the stored param set, so the ENGINE re-validates it
                #     when the wave actually fires;
                #   * the engine's self-guard / wrong-box guard / ping gate / consent
                #     flow all run untouched at fire time - this route only defers WHEN.
                # It is restart-only ON PURPOSE. There is no generic "arm any action"
                # facility: an unattended-execution path for arbitrary tools is a much
                # larger safety problem. Any other tool asking for 'arm-dispatch' falls
                # through to the action route below and 404s as an unknown action.
                if ($verb -eq 'POST' -and $path -eq '/api/tool/restart/action/arm-dispatch') {
                    if (-not ($state.AckGiven -and $null -ne $state.Cred)) {
                        & $writeJson $resp @{ error = 'Admin session required: set ADW credentials and accept responsibility (Start Admin Session) before arming a restart wave.' } 403; continue
                    }
                    if ($state.ArmedRestart) {
                        & $writeJson $resp @{ error = 'a restart wave is already armed on this server - disarm it before arming another.' } 409; continue
                    }
                    if ($req.ContentLength64 -gt 26214400) { & $writeJson $resp @{ error='request body too large (25 MB cap)' } 413; continue }
                    $armRaw = ''
                    if ($req.HasEntityBody) {
                        try { $armRaw = & $readBody $req 26214400 } catch { & $writeJson $resp @{ error = $_.Exception.Message } 413; continue }
                    }
                    $armBody = $null
                    if ($armRaw) { try { $armBody = ConvertFrom-Json $armRaw } catch { $armBody = $null } }
                    if (-not $armBody) { & $writeJson $resp @{ error = 'invalid JSON body (expected { fireAt, params })' } 400; continue }
                    $armParams = @{}
                    if ($armBody.params) { foreach ($ap in $armBody.params.PSObject.Properties) { $armParams[$ap.Name] = $ap.Value } }
                    # '__job' is the server's own injection slot (the cancel bridge); a
                    # client must never be able to seed it.
                    if ($armParams.ContainsKey('__job')) { [void]$armParams.Remove('__job') }
                    $fireRaw = [string]$armBody.fireAt
                    if ([string]::IsNullOrWhiteSpace($fireRaw)) { $fireRaw = [string]$armParams['restartTime'] }
                    $chk = Test-JanetWebArmRequest -Params $armParams -FireAtRaw $fireRaw -Now (Get-Date) -MaxHours $armMaxHours
                    if (-not $chk.ok) { & $writeJson $resp @{ error = [string]$chk.error } 400; continue }
                    $newArm = New-JanetWebArmedRestart -Params $armParams -FireAt ([datetime]$chk.fireAt) `
                                -SessionId ([string]$state.LogCtx.SessionId) -Operator ([string]$state.LogCtx.Operator) `
                                -DryRun ([bool]$chk.dryRun) -Mode ([string]$armBody.mode)
                    $state.ArmedRestart = $newArm
                    try { Write-Host ("  [armed restart] ARMED by $($newArm.Operator): $($newArm.HostCount) host(s) fire at $(([datetime]$newArm.FireAt).ToString('yyyy-MM-dd HH:mm:ss'))$(if ($newArm.DryRun) { ' (DRY RUN)' })") -ForegroundColor Cyan } catch {}
                    try { Write-JanetWebSessionLog -Context $state.LogCtx -Tool 'restart' -Action 'ARM:armed' -Target "(armed dispatch - $($newArm.HostCount) host(s))" -Result 'Armed' -Detail ("fireAt=$(([datetime]$newArm.FireAt).ToString('s')) dryRun=$($newArm.DryRun) mode=$($newArm.Mode)") } catch {}
                    & $writeJson $resp @{ ok = $true; armed = (& $armSummary $newArm) }
                    continue
                }

                # POST /api/tool/<id>/action/<actionId>
                if ($verb -eq 'POST' -and $seg.Count -eq 5 -and $seg[1] -eq 'tool' -and $seg[3] -eq 'action') {
                    # Sweep finished jobs FIRST so a freed stateful Busy slot is seen
                    # by this request (a cancelled reports/stig run must not 409-lock
                    # the tool until someone happens to poll /events).
                    & $reapJobs ''
                    $toolId = $seg[2]; $actId = $seg[4]
                    $mp = $state.ModulePaths[$toolId]
                    if (-not $mp) { & $writeJson $resp @{ error = 'tool manifest unavailable' } 404; continue }
                    $mani = $state.Manifests[$toolId]
                    $knownIds = @(); if ($mani -and $mani.actions) { $knownIds = @($mani.actions | ForEach-Object { $_.id }) }
                    if (($knownIds -notcontains $actId) -and -not ($toolId -eq 'acas' -and $acasByIdActions -contains $actId)) {
                        & $writeJson $resp @{ error = "unknown action '$actId' for tool '$toolId'" } 404; continue
                    }
                    $toolVer = '1.0.0'; if ($mani -and $mani.version) { $toolVer = [string]$mani.version }

                    # Server-side session gate (FAIL-CLOSED as of loop 5): a DESTRUCTIVE
                    # (state-changing) action requires an admin session = responsibility
                    # ack (POST /session/start) AND a set credential. This backstops the
                    # browser gate. The default is now DENY: an action is destructive
                    # UNLESS it POSITIVELY asserts read-only (explicit destructive=$false).
                    # A manifest action that OMITS the 'destructive' key is treated as
                    # state-changing and gated, so a future unflagged action can never
                    # silently run without a session (was: default ALLOW - the latent hole
                    # this loop closes). Read-only actions (scans/queries/adsearch) still
                    # run without a session because each is explicitly destructive=$false.
                    # NOTE: manifest actions are raw hashtables, so key presence is tested
                    # with IDictionary.Contains - PSObject.Properties does NOT surface
                    # hashtable keys. The ACAS by-id set governs ONLY actions ABSENT from
                    # the manifest ($actObj null); a by-id action that also lives in the
                    # manifest is ruled by its manifest flag (so its explicit destructive
                    # flag is never weakened by the by-id read-only list).
                    $actObj = $null; if ($mani -and $mani.actions) { $actObj = $mani.actions | Where-Object { $_.id -eq $actId } | Select-Object -First 1 }
                    $isDestructive = $true
                    if ($actObj) {
                        $hasFlag = if ($actObj -is [System.Collections.IDictionary]) { $actObj.Contains('destructive') } else { [bool]$actObj.PSObject.Properties['destructive'] }
                        if ($hasFlag -and (-not $actObj.destructive)) { $isDestructive = $false }
                    } elseif ($toolId -eq 'acas' -and $acasByIdActions -contains $actId) {
                        $isDestructive = [bool]($acasByIdDestructive -contains $actId)
                    }
                    if ($isDestructive -and -not ($state.AckGiven -and $null -ne $state.Cred)) {
                        & $writeJson $resp @{ error = 'Admin session required: set ADW credentials and accept responsibility (Start Admin Session) before running actions that change machines.' } 403; continue
                    }

                    if ($req.ContentLength64 -gt 26214400) { & $writeJson $resp @{ error='request body too large (25 MB cap)' } 413; continue }
                    # body -> params hashtable
                    $params = @{}
                    if ($req.HasEntityBody) {
                        $raw = ''
                        try { $raw = & $readBody $req 26214400 } catch { & $writeJson $resp @{ error = $_.Exception.Message } 413; continue }
                        if ($raw) { try { foreach ($p in (ConvertFrom-Json $raw).PSObject.Properties) { $params[$p.Name] = $p.Value } } catch {} }
                    }

                    # (audit 2026-07-23: the ACAS uploaded-CSV archive copy moved off this
                    # accept thread into the spawned worker below - a slow share Copy-Item
                    # stalled every request while it ran.)

                    # Create + start the job through the shared launcher. The armed-restart
                    # tick fires the SAME way, so there is exactly ONE job-start code path.
                    $jr = & $startToolJob $toolId $actId $params $toolVer $mani $mp
                    if ($jr -is [array]) { $jr = $jr[-1] }
                    if (-not $jr.ok) { & $writeJson $resp @{ error = [string]$jr.error } ([int]$jr.code); continue }
                    & $writeJson $resp @{ jobId = [string]$jr.jobId }
                    continue
                }

                # GET /api/job/<jobId>/events?since=N
                if ($verb -eq 'GET' -and $seg.Count -eq 4 -and $seg[1] -eq 'job' -and $seg[3] -eq 'events') {
                    # Sweep every job (drain finished runspaces, evict stale ones) but
                    # never evict the job THIS poll is about - even one that finished
                    # >5 min ago must still deliver its final summary to this request.
                    & $reapJobs $seg[2]
                    $job = $state.Jobs[$seg[2]]
                    if (-not $job) { & $writeJson $resp @{ error='no such job' } 404; continue }
                    $since = 0; [int]::TryParse([string]$req.QueryString['since'], [ref]$since) | Out-Null
                    if ($since -lt 0) { $since = 0 } elseif ($since -gt 0) { $sc = $job.Events.Count; if ($since -gt $sc) { $since = $sc } }
                    # Status BEFORE the events snapshot: a worker finishing in between
                    # would otherwise report a terminal status without its final event
                    # (the client stops polling at terminal). This way the final event
                    # is already in the snapshot - or status still reads as live.
                    $statusNow = [string]$job.Status
                    # Tail-only snapshot: copy just Events[$since..] instead of cloning the
                    # whole synchronized ArrayList every ~400ms poll (was O(total events),
                    # now O(new events)). Count + GetRange must be one atomic step - hold the
                    # SyncRoot lock (GetRange on a synchronized ArrayList is NOT atomic by
                    # itself) and copy the range to a plain array inside the lock.
                    $new = @(); $count = 0
                    $evtRoot = $job.Events.SyncRoot
                    [System.Threading.Monitor]::Enter($evtRoot)
                    try {
                        $count = $job.Events.Count
                        if ($count -gt $since) { $new = $job.Events.GetRange($since, $count - $since).ToArray() }
                    } finally { [System.Threading.Monitor]::Exit($evtRoot) }
                    # Clean up the runspace only once it has actually finished, so a
                    # cancelling worker (still stopping its WinRM children) never blocks
                    # this poll / the accept loop. (audit 2026-07-23: shared $drainJob -
                    # this was a hand-rolled copy of the reaper's drain.)
                    & $drainJob $job
                    & $writeJson $resp @{ status=$statusNow; nextSince=$count; events=@($new) }
                    continue
                }

                # POST /api/job/<jobId>/cancel
                if ($verb -eq 'POST' -and $seg.Count -eq 4 -and $seg[1] -eq 'job' -and $seg[3] -eq 'cancel') {
                    & $reapJobs $seg[2]
                    $job = $state.Jobs[$seg[2]]
                    # Only a still-running job can be cancelled (a finished one must
                    # keep its done/error status). 'cancelling' is a LIVE status: the
                    # client keeps polling so the engine's late abandon rows reach the
                    # operator; the worker maps it to 'cancelled' when it completes.
                    if ($job -and $job.Status -eq 'running') {
                        # Graceful: the fan-out polls Cancel, breaks, and BeginStops its
                        # in-flight WinRM children. (Hard-stopping the outer runspace here
                        # would skip that and leave remote patch/reboot calls running.)
                        $job['Cancel'] = $true
                        $job.Status = 'cancelling'
                        [void]$job.Events.Add(@{ type='log'; level='warn'; text='Cancel requested - stopping in-flight work...' })
                    }
                    & $writeJson $resp @{ ok = $true }
                    continue
                }

                & $writeJson $resp @{ error = "no route for $verb $path" } 404
            } catch {
                # Log the full exception + stack trace to the server console only; the
                # client gets a generic body so a raw message can't leak UNC/filesystem paths.
                $ex = $_
                try { Write-Host ("  [500] $verb $path -> $($ex.Exception.Message)`r`n$($ex.ScriptStackTrace)") -ForegroundColor Red } catch {}
                try { & $writeJson $ctx.Response @{ error = 'internal error - see server console' } 500 } catch {}
            }
        }
    } finally {
        try { Write-JanetWebRollup -Context $state.LogCtx -ClosingNotes $state.ClosingNotes } catch {}
        foreach ($slot in $state.ToolRunspaces.Values) { try { $slot.RS.Close(); $slot.RS.Dispose() } catch {} }
        try { $listener.Stop(); $listener.Close() } catch {}
        Write-Host "  JANET Web stopped." -ForegroundColor DarkGray
    }
}
