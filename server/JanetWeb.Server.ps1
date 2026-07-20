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
    $leaf = [System.IO.Path]::GetFileName($rel)
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
    $uploadsDir = Join-Path $env:TEMP 'JanetWeb\uploads'
    try { if (Test-Path -LiteralPath $uploadsDir) { Remove-Item -LiteralPath $uploadsDir -Recurse -Force -ErrorAction SilentlyContinue } } catch {}
    try { New-Item -ItemType Directory -Path $uploadsDir -Force -ErrorAction SilentlyContinue | Out-Null } catch {}

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
            $shareHost = if ($JanetPackageShare -match '^\\\\([^\\]+)') { $Matches[1] } else { $null }
            $shareUp = $false
            if ($shareHost) { try { $shareUp = [bool](Test-JanetWebHostReachable $shareHost) } catch {} }
            if ($shareUp -and (Test-Path -LiteralPath $JanetPackageShare)) { $packagesDir = $JanetPackageShare }
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
    }

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
            if ($j.Status -ne 'running' -and $j.PS -and $j.Async -and $j.Async.IsCompleted) {
                try { $j.PS.EndInvoke($j.Async) | Out-Null } catch {}
                try { $j.PS.Dispose() } catch {}   # disposes the [powershell] only; a persistent tool runspace is assigned, not owned, so it stays open
                if ($j.ContainsKey('RS') -and $j.RS) { try { $j.RS.Close(); $j.RS.Dispose() } catch {}; $j.RS = $null }
                $j.PS = $null; $j.Async = $null
                # cancel raced the worker's own completion: the worker is gone, so
                # nothing else will ever map 'cancelling' to a terminal status
                if ($j.Status -eq 'cancelling') { $j.Status = 'cancelled' }
                # free the stateful tool's serialized slot for the next action
                if ($j.Tool -and $state.ToolRunspaces.ContainsKey($j.Tool)) { $state.ToolRunspaces[$j.Tool].Busy = $false }
            }
            # 'cancelling' counts as live: the worker is still draining its abandon
            # events and will stamp FinishedAt when it maps itself to 'cancelled'.
            if ($j.Status -eq 'running' -or $j.Status -eq 'cancelling') { continue }
            if (-not $j.FinishedAt) { $j.FinishedAt = Get-Date }   # backstop for any path that missed the stamp
            if (-not $j.PS -and $k -ne $keepJobId -and ((Get-Date) - $j.FinishedAt).TotalMinutes -gt 5) { [void]$state.Jobs.Remove($k) }
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
                        & $writeBytes $resp ([System.IO.File]::ReadAllBytes($asset)) 200 (& $contentType ([System.IO.Path]::GetExtension($asset)))
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
                    if ($verb -eq 'DELETE') { $state.Cred = $null; $state.AckGiven = $false; & $writeJson $resp @{ ok=$true; status=(Get-JanetWebCredentialStatus -Credential $null) }; continue }
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
                    # Ping-gate a share-hosted CSV first, and tail it instead of
                    # full-reading: this runs on the single-threaded accept loop.
                    $tailOk = Test-JanetWebShare -Root $file
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
                    $tailOk = Test-JanetWebShare -Root $file
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
                    $rid = [guid]::NewGuid().ToString('N')
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
                    $pkgRootOk = $true
                    if ($packagesDir -match '^\\\\([^\\]+)') {
                        $pkgRootOk = (Test-JanetWebHostReachable $Matches[1])
                    }
                    if ($pkgRootOk -and (Test-Path -LiteralPath $packagesDir)) {
                        foreach ($d in (Get-ChildItem -LiteralPath $packagesDir -Directory -ErrorAction SilentlyContinue | Sort-Object Name)) {
                            $hasPsadt = $false; $msiCount = 0
                            try { $hasPsadt = [bool](Get-ChildItem -LiteralPath $d.FullName -Filter 'Deploy-Application.ps1' -Recurse -Depth 4 -File -ErrorAction SilentlyContinue | Select-Object -First 1) } catch {}
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
                    # Arbitrary operator path: ping-gate a UNC host so a dead share
                    # can't hang the accept loop on Test-Path/enumeration.
                    $bpOk = $true
                    if ($bp -match '^\\\\([^\\]+)') {
                        $bpOk = (Test-JanetWebHostReachable $Matches[1])
                    }
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

                    # ACAS: retain a timestamped archive copy of each uploaded CSV (once
                    # per unique source) next to this operator's ACAS logs - an audit trail
                    # of exactly what was imported. Best-effort; never blocks the action.
                    if ($toolId -eq 'acas' -and $params['csvPaths']) {
                        try {
                            $lc = $state.LogCtx
                            $archRoot = if ($lc.OnShare) { $lc.NetRoot } else { $lc.JanetLocal }
                            # The DESTINATION can be a share too - ping-gate it like the
                            # UNC sources below. The throw lands in this block's empty
                            # catch: archiving is skipped this pass and (since nothing
                            # was added to ArchivedCsvs) retried on the next action.
                            if ($archRoot -match '^\\\\([^\\]+)') {
                                if (-not (Test-JanetWebHostReachable $Matches[1])) { throw 'archive share unreachable' }
                            }
                            $archDir = Join-Path (Join-Path (Join-Path $archRoot (Resolve-JanetWebToolName -ToolId 'acas')) $lc.UserFolder) 'CsvArchive'
                            foreach ($cp in ([string]$params['csvPaths'] -split "`r?`n")) {
                                $src = $cp.Trim().Trim('"'); if (-not $src) { continue }
                                if ($state.ArchivedCsvs.Contains($src)) { continue }
                                # Uploaded CSVs are local temp paths (fast). A manually-typed UNC
                                # source must be ping-gated first so an unreachable share can't
                                # block Test-Path/Copy-Item on the single-threaded accept loop.
                                if ($src -match '^\\\\([^\\]+)') {
                                    if (-not (Test-JanetWebHostReachable $Matches[1])) { [void]$state.ArchivedCsvs.Add($src); continue }
                                }
                                if (-not (Test-Path -LiteralPath $src)) { continue }
                                [void]$state.ArchivedCsvs.Add($src)
                                if (-not (Test-Path -LiteralPath $archDir)) { New-Item -ItemType Directory -Path $archDir -Force -ErrorAction Stop | Out-Null }
                                $dest = Join-Path $archDir ((Get-Date -Format 'yyyy-MM-dd_HHmmss') + '_' + (Split-Path -Leaf $src))
                                Copy-Item -LiteralPath $src -Destination $dest -Force -ErrorAction Stop
                            }
                        } catch {}
                    }

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
                    $params['__job'] = $job

                    $worker = {
                        param($modulePath, $actionId, $prms, $cred, $job, $logScript, $logCtx, $toolId, $skipImport, $toolVer)
                        try {
                            # Stateful tools run in a persistent runspace where the module +
                            # logging script were imported ONCE at runspace creation;
                            # re-importing would reset $script: state, so skip it for them.
                            if (-not $skipImport) {
                                . $logScript
                                Import-Module $modulePath -Force -ErrorAction Stop
                            }
                            # The manifest ToolVersion rides to the audit CSV only when the
                            # loaded logging bridge has the (optional) parameter, so the two
                            # changes can land in either order.
                            # Tools whose audit target IS a machine -> they get a per-host TouchedHosts
                            # CSV. Excludes reports (filenames), dhcp (scope names), adsearch (directory objects).
                            $hostTouchingTool = @('wpt','acas','pkginstall','winupgrade','upr','secureboot','restart','message','remoteadmin') -contains $toolId
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
                                        $tgt = [string]$e.target
                                        if ($tgt -and $tgt -ne 'N/A' -and $tgt -ne '(custom command)') {
                                            $thHost = ($tgt -split '\\')[0]   # upr emits "host\product" -> keep the host
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
                                & $writeJson $resp @{ error = 'internal error - see server console' } 500; continue
                            }
                        }
                        $slot = $state.ToolRunspaces[$toolId]
                        if ($slot.Busy) {
                            [void]$state.Jobs.Remove($jobId)
                            & $writeJson $resp @{ error = "$toolId is busy with another action - wait for it to finish, then retry." } 409; continue
                        }
                        $slot.Busy = $true
                        $ps = [powershell]::Create(); $ps.Runspace = $slot.RS
                        [void]$ps.AddScript($worker).AddArgument($mp).AddArgument($actId).AddArgument($params).AddArgument($state.Cred).AddArgument($job).AddArgument($state.LogScript).AddArgument($state.LogCtx).AddArgument($toolId).AddArgument($true).AddArgument($toolVer)
                    } else {
                        $ps = [powershell]::Create()
                        [void]$ps.AddScript($worker).AddArgument($mp).AddArgument($actId).AddArgument($params).AddArgument($state.Cred).AddArgument($job).AddArgument($state.LogScript).AddArgument($state.LogCtx).AddArgument($toolId).AddArgument($false).AddArgument($toolVer)
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
                        & $writeJson $resp @{ error = 'internal error - see server console' } 500
                        continue
                    }
                    & $writeJson $resp @{ jobId = $jobId }
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
                    # this poll / the accept loop.
                    if ($job.Status -ne 'running' -and $job.PS -and $job.Async -and $job.Async.IsCompleted) {
                        try { $job.PS.EndInvoke($job.Async) | Out-Null } catch {}
                        try { $job.PS.Dispose() } catch {}
                        if ($job.ContainsKey('RS') -and $job.RS) { try { $job.RS.Close(); $job.RS.Dispose() } catch {}; $job.RS = $null }
                        $job.PS = $null; $job.Async = $null
                        if ($job.Status -eq 'cancelling') { $job.Status = 'cancelled' }   # worker already gone - finalize a raced cancel
                        if ($job.Tool -and $state.ToolRunspaces.ContainsKey($job.Tool)) { $state.ToolRunspaces[$job.Tool].Busy = $false }
                    }
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
