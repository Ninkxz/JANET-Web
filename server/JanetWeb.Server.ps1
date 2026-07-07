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
#    GET/POST/DELETE /api/schedule[/<id>]             -> off-hours scheduler (arm/list/cancel)
#    GET    /api/dashboard                            -> hub rollup (flat files only, touches no hosts)
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

function Start-JanetWebServer {
    param(
        [Parameter(Mandatory)] [string]$Root,
        [int]$Port = 8089,
        [Parameter(Mandatory)] [string]$Token,
        [string]$Asi = '',
        [string]$PackagesRoot = ''
    )

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

    # Off-hours scheduler store: one JSON per armed wave (JanetLocal\schedule\<id>.json).
    # A background poller (started after the listener binds) fires a due wave by POSTing
    # to this same server's gated action route over loopback - so the wave runs through
    # the identical admin-session ack+cred gate + engine guards, with no new bypass path.
    $scheduleDir = Join-Path (Join-Path $Root 'JanetLocal') 'schedule'

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
    # Name is frozen (TWO-era): existing operator environments already set
    # JANET2_PACKAGES_ROOT, so renaming it would silently break their override.
    $env:JANET2_PACKAGES_ROOT = $packagesDir
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

    # --- Off-hours scheduler poller (own runspace) -----------------------------
    # A separate thread so it can make a LOOPBACK POST to this server (the accept
    # loop serves it on its own thread - no self-deadlock) to fire a due wave
    # through the normal gated dispatch. It never touches engines directly and
    # holds no credential; the wave uses the server's in-memory admin session at
    # fire time (fail-safe: if that's gone, the gated route 403s and the schedule
    # is marked blocked).
    try {
        $schedPoller = {
            param($Port, $Token, $SchedDir)
            function Save-Sched {
                param($Obj, $Path)
                try {
                    $tmp = "$Path.tmp"
                    [System.IO.File]::WriteAllText($tmp, ($Obj | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
                    Move-Item -LiteralPath $tmp -Destination $Path -Force
                } catch {}
            }
            while ($true) {
                Start-Sleep -Seconds 15
                if (-not (Test-Path -LiteralPath $SchedDir)) { continue }
                $now = [DateTime]::UtcNow
                foreach ($f in @(Get-ChildItem -LiteralPath $SchedDir -Filter '*.json' -File -ErrorAction SilentlyContinue)) {
                    $o = $null
                    try {
                        $raw = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop
                        if ($raw -and $raw.Length -gt 0 -and [int]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }
                        if ([string]::IsNullOrWhiteSpace($raw)) { continue }
                        $o = ConvertFrom-Json $raw
                    } catch { continue }
                    if ([string]$o.status -ne 'armed') { continue }
                    $fireDt = [DateTime]::MinValue
                    if (-not [DateTime]::TryParse([string]$o.fireAtUtc, [ref]$fireDt)) { continue }
                    if ($fireDt.ToUniversalTime() -gt $now) { continue }   # not due yet
                    # Fire: loopback POST to the gated action route.
                    $bodyObj = @{}
                    if ($o.params) { foreach ($pp in $o.params.PSObject.Properties) { $bodyObj[$pp.Name] = $pp.Value } }
                    $bodyJson = if ($bodyObj.Count -gt 0) { $bodyObj | ConvertTo-Json -Depth 6 -Compress } else { '{}' }
                    $bytes = [System.Text.Encoding]::UTF8.GetBytes($bodyJson)
                    $code = 0; $respText = ''
                    try {
                        $req = [System.Net.HttpWebRequest]::Create("http://127.0.0.1:$Port/api/tool/$($o.toolId)/action/$($o.actionId)")
                        $req.Method = 'POST'; $req.Timeout = 30000; $req.ContentType = 'application/json'
                        $req.Headers.Add('X-Janet-Token', $Token)
                        $req.ContentLength = $bytes.Length
                        $rs = $req.GetRequestStream(); $rs.Write($bytes, 0, $bytes.Length); $rs.Close()
                        $resp = $req.GetResponse(); $code = [int]$resp.StatusCode
                        $respText = (New-Object IO.StreamReader($resp.GetResponseStream())).ReadToEnd(); $resp.Close()
                    } catch [System.Net.WebException] {
                        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode; try { $respText = (New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())).ReadToEnd() } catch {} }
                        else { $code = -1; $respText = $_.Exception.Message }
                    } catch { $code = -1; $respText = $_.Exception.Message }

                    $o.firedUtc = ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))
                    if ($code -ge 200 -and $code -lt 300) {
                        # Record the actual engine job id alongside the HTTP acceptance code so
                        # the ledger entry is traceable to a real dispatched job, not just "the
                        # POST was accepted" (acceptance-vs-outcome).
                        $fireJobId = ''
                        try { $fireJobId = [string]((ConvertFrom-Json $respText).jobId) } catch {}
                        $o.note = if ($fireJobId) { "fired ok (HTTP $code, job $fireJobId)" } else { "fired ok (HTTP $code)" }
                        if (([string]$o.recurrence) -eq 'daily' -or ([string]$o.recurrence) -eq 'weekly') {
                            # Advance to the NEXT FUTURE occurrence rather than a single increment,
                            # so a server/session outage spanning multiple periods can't cause a
                            # rapid-refire loop (the poller would otherwise keep seeing a past
                            # fireAtUtc every ~15s until it caught up to now).
                            $incDays = if (([string]$o.recurrence) -eq 'daily') { 1 } else { 7 }
                            $next = $fireDt.ToUniversalTime()
                            do { $next = $next.AddDays($incDays) } while ($next -le [DateTime]::UtcNow)
                            $o.fireAtUtc = $next.ToString('yyyy-MM-ddTHH:mm:ssZ'); $o.status = 'armed'
                        }
                        else { $o.status = 'fired' }
                    } elseif ($code -eq 403) {
                        $o.status = 'blocked'; $o.note = 'admin session not live at fire time - re-arm after Start Admin Session'
                    } else {
                        $o.status = 'error'; $o.note = "fire failed (HTTP $code): $($respText.Substring(0, [Math]::Min(200, $respText.Length)))"
                    }
                    Save-Sched -Obj $o -Path $f.FullName
                }
            }
        }
        $schedPs = [System.Management.Automation.PowerShell]::Create()
        $schedRs = [runspacefactory]::CreateRunspace(); $schedRs.Open()
        $schedPs.Runspace = $schedRs
        [void]$schedPs.AddScript($schedPoller).AddArgument($Port).AddArgument($Token).AddArgument($scheduleDir)
        $schedAsync = $schedPs.BeginInvoke()
        $state.SchedPoller = @{ Ps = $schedPs; Rs = $schedRs; Async = $schedAsync }
        Write-Host "  Off-hours scheduler poller started (15 s tick)." -ForegroundColor DarkGray
    } catch { try { Write-Host "  Scheduler poller failed to start: $($_.Exception.Message)" -ForegroundColor Yellow } catch {} }

    $pendingAccept = $null
    try {
        while ($listener.IsListening) {
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

                # ---- static assets (no token; UI code only) ----
                if ($path -notlike '/api/*') {
                    $rel = if ($path -eq '/' -or [string]::IsNullOrEmpty($path)) { 'index.html' } else { $path.TrimStart('/') }
                    # audit#28: never serve a dev/underscore-prefixed asset from the
                    # production web root (e.g. _devtest.html, _stub.view.js) - they are
                    # dev-only harnesses that bypass the client gate and expose the tool
                    # catalog. 404 any request whose leaf name starts with '_'.
                    $leaf = [System.IO.Path]::GetFileName($rel)
                    if ($leaf -and $leaf.StartsWith('_')) {
                        & $writeBytes $resp ([System.Text.Encoding]::UTF8.GetBytes('not found')) 404 'text/plain'
                        continue
                    }
                    $full = Join-Path $webDir ($rel -replace '/', '\')
                    # path-traversal guard: resolved file must stay under web/
                    $resolved = $null
                    try { $resolved = (Resolve-Path -LiteralPath $full -ErrorAction Stop).Path } catch {}
                    $webGuard = $webDir.TrimEnd('\','/') + [System.IO.Path]::DirectorySeparatorChar   # trailing sep so a sibling 'web2' can't pass the prefix check
                    if ($resolved -and $resolved.StartsWith($webGuard, [StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $resolved -PathType Leaf)) {
                        & $writeBytes $resp ([System.IO.File]::ReadAllBytes($resolved)) 200 (& $contentType ([System.IO.Path]::GetExtension($resolved)))
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
                if ($verb -eq 'GET' -and $path -eq '/api/report-preview') {
                    $rid = [string]$req.QueryString['id']
                    $rp = $null; if (-not [string]::IsNullOrWhiteSpace($rid)) { $rp = $state.ReportPreviews[$rid] }
                    if ($rp) { [void]$state.ReportPreviews.Remove($rid) }
                    $reportCsp = "default-src 'self'; script-src 'unsafe-inline' 'self'; style-src 'unsafe-inline' 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'"
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
                    if ($verb -eq 'DELETE') { $state.Cred = $null; & $writeJson $resp @{ ok=$true; status=(Get-JanetWebCredentialStatus -Credential $null) }; continue }
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

                # ---- Off-hours scheduler (arm-and-walk-away) ----------------------
                # GET  /api/schedule            -> list armed + recent schedules
                # POST /api/schedule            -> arm a wave (armed to fire at fireAt)
                # DELETE /api/schedule/<id>      -> cancel an armed schedule
                # A schedule is a stored intent only; the background poller fires it by
                # POSTing to /api/tool/<tool>/action/<action> over loopback, so the wave
                # goes through the SAME destructive gate (ack+cred) + engine guards. A
                # destructive wave therefore only fires if an admin session is still live
                # on this server process at fire time (fail-safe if the box rebooted).
                if ($path -eq '/api/schedule' -or $path -like '/api/schedule/*') {
                    if (-not (Test-Path -LiteralPath $scheduleDir)) { try { New-Item -ItemType Directory -Path $scheduleDir -Force -ErrorAction SilentlyContinue | Out-Null } catch {} }

                    if ($verb -eq 'GET' -and $path -eq '/api/schedule') {
                        $items = New-Object System.Collections.ArrayList
                        try {
                            foreach ($f in @(Get-ChildItem -LiteralPath $scheduleDir -Filter '*.json' -File -ErrorAction SilentlyContinue)) {
                                try {
                                    $sraw = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop
                                    if ($sraw -and $sraw.Length -gt 0 -and [int]$sraw[0] -eq 0xFEFF) { $sraw = $sraw.Substring(1) }
                                    if (-not [string]::IsNullOrWhiteSpace($sraw)) { [void]$items.Add((ConvertFrom-Json $sraw)) }
                                } catch {}
                            }
                        } catch {}
                        $sorted = @($items | Sort-Object -Property @{ Expression = { [string]$_.fireAtUtc } })
                        & $writeJson $resp @{ ok=$true; schedules=@($sorted) }
                        continue
                    }

                    if ($verb -eq 'POST' -and $path -eq '/api/schedule') {
                        if ($req.ContentLength64 -gt 1048576) { & $writeJson $resp @{ error='schedule body too large' } 413; continue }
                        $sbody = @{}
                        if ($req.HasEntityBody) {
                            $sraw = ''; try { $sraw = & $readBody $req 1048576 } catch { & $writeJson $resp @{ error=$_.Exception.Message } 413; continue }
                            if ($sraw) { try { foreach ($pp in (ConvertFrom-Json $sraw).PSObject.Properties) { $sbody[$pp.Name] = $pp.Value } } catch { & $writeJson $resp @{ error='invalid JSON body' } 400; continue } }
                        }
                        $sTool = [string]$sbody['toolId']; $sAct = [string]$sbody['actionId']
                        if (-not $sTool -or -not $sAct) { & $writeJson $resp @{ error='toolId and actionId are required' } 400; continue }
                        $sMani = $state.Manifests[$sTool]
                        if (-not $sMani) { & $writeJson $resp @{ error="unknown tool '$sTool'" } 404; continue }
                        $sKnown = @(); if ($sMani.actions) { $sKnown = @($sMani.actions | ForEach-Object { $_.id }) }
                        $sActObj = $null; if ($sMani.actions) { $sActObj = $sMani.actions | Where-Object { $_.id -eq $sAct } | Select-Object -First 1 }
                        if (($sKnown -notcontains $sAct) -and -not ($sTool -eq 'acas' -and $acasByIdActions -contains $sAct)) {
                            & $writeJson $resp @{ error="unknown action '$sAct' for tool '$sTool'" } 404; continue
                        }
                        $sDestructive = ($sActObj -and $sActObj.destructive) -or ($sTool -eq 'acas' -and $acasByIdDestructive -contains $sAct)
                        # ARMING any wave requires the admin session up front, so an unattended
                        # wave can only be scheduled by an authenticated operator (a bare token-
                        # holder must not be able to leave standing automation armed). Destructive
                        # waves stay additionally fail-safe via the live-session check at fire time.
                        if (-not ($state.AckGiven -and $null -ne $state.Cred)) {
                            & $writeJson $resp @{ error='Admin session required to arm a schedule: set ADW credentials and Start Admin Session first.' } 403; continue
                        }
                        # Parse fireAt (accept ISO 8601, local or Z). Reject a past time (>2 min ago).
                        $fireStr = [string]$sbody['fireAt']
                        $fireDt = [DateTime]::MinValue
                        if (-not [DateTime]::TryParse($fireStr, [ref]$fireDt)) { & $writeJson $resp @{ error="could not parse fireAt '$fireStr' (use ISO 8601)" } 400; continue }
                        $fireUtc = $fireDt.ToUniversalTime()
                        if ($fireUtc -lt ([DateTime]::UtcNow.AddMinutes(-2))) { & $writeJson $resp @{ error='fireAt is in the past' } 400; continue }
                        $rec = ([string]$sbody['recurrence']).ToLower(); if ($rec -notin @('none','daily','weekly')) { $rec = 'none' }
                        # Recurrence is a destructive-wave convenience only (a recurring destructive
                        # wave stays fail-safe via the live-admin-session check at fire time). A
                        # recurring NON-destructive wave is exactly the standing unattended scan
                        # automation the operating model forbids, so non-destructive waves are one-shot.
                        if (-not $sDestructive -and $rec -ne 'none') {
                            & $writeJson $resp @{ error='recurrence is a destructive-wave convenience; non-destructive waves are one-shot' } 400; continue
                        }
                        $sParams = @{}
                        if ($sbody['params'] -and $sbody['params'] -is [System.Management.Automation.PSCustomObject]) { foreach ($pp in $sbody['params'].PSObject.Properties) { $sParams[$pp.Name] = $pp.Value } }
                        $sid = [guid]::NewGuid().ToString('N')
                        $sObj = [ordered]@{
                            id = $sid
                            createdUtc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
                            createdBy = $state.LogCtx.Operator
                            toolId = $sTool; actionId = $sAct
                            label = $(if ($sbody['label']) { [string]$sbody['label'] } else { "$sTool / $sAct" })
                            destructive = [bool]$sDestructive
                            fireAtUtc = $fireUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
                            recurrence = $rec
                            status = 'armed'
                            params = $sParams
                            firedUtc = ''
                            note = ''
                        }
                        try {
                            $sfile = Join-Path $scheduleDir ("$sid.json")
                            $stmp = "$sfile.tmp"
                            [System.IO.File]::WriteAllText($stmp, (($sObj | ConvertTo-Json -Depth 6)), (New-Object System.Text.UTF8Encoding($false)))
                            Move-Item -LiteralPath $stmp -Destination $sfile -Force -ErrorAction Stop
                        } catch { & $writeJson $resp @{ ok=$false; error="could not save schedule: $($_.Exception.Message)" } 500; continue }
                        & $writeJson $resp @{ ok=$true; id=$sid; fireAtUtc=$sObj.fireAtUtc; destructive=[bool]$sDestructive }
                        continue
                    }

                    if ($verb -eq 'DELETE' -and $path -like '/api/schedule/*') {
                        $sid = ($path -split '/')[-1]
                        if ($sid -notmatch '^[0-9a-fA-F]{32}$') { & $writeJson $resp @{ error='bad schedule id' } 400; continue }
                        $sfile = Join-Path $scheduleDir ("$sid.json")
                        if (-not (Test-Path -LiteralPath $sfile)) { & $writeJson $resp @{ error='not found' } 404; continue }
                        # Mark cancelled (keep a record) rather than hard-delete.
                        try {
                            $sraw = Get-Content -LiteralPath $sfile -Raw -ErrorAction Stop
                            if ($sraw -and $sraw.Length -gt 0 -and [int]$sraw[0] -eq 0xFEFF) { $sraw = $sraw.Substring(1) }
                            $sObj = ConvertFrom-Json $sraw
                            $sObj.status = 'cancelled'
                            $dtmp = "$sfile.tmp"
                            [System.IO.File]::WriteAllText($dtmp, (($sObj | ConvertTo-Json -Depth 6)), (New-Object System.Text.UTF8Encoding($false)))
                            Move-Item -LiteralPath $dtmp -Destination $sfile -Force -ErrorAction Stop
                        } catch { & $writeJson $resp @{ ok=$false; error=$_.Exception.Message } 500; continue }
                        & $writeJson $resp @{ ok=$true; id=$sid; status='cancelled' }
                        continue
                    }
                }

                # GET /api/dashboard -> read-only Mission Board status strip for the hub.
                # FLAT FILES ONLY: never touches a host, never spins a runspace. Reads the
                # newest WPT bulk-scan snapshot (age / pending / reboot / stuck-host streak),
                # the SLA firstSeen ledger (size + severity/kev breakdown + oldest firstSeen
                # age, the ledger alone - no live join), and the KEV catalog (size + mtime).
                # Each section degrades to present=$false when its file is absent so the UI
                # renders a neutral tile. Runs on the accept loop; work is bounded (newest 60).
                if ($verb -eq 'GET' -and $path -eq '/api/dashboard') {
                    $jlDir   = Join-Path $Root 'JanetLocal'
                    $snapDir = Join-Path $jlDir 'snapshots'
                    $ledPath = Join-Path $jlDir 'sla-ledger.json'
                    $kevPath = Join-Path $jlDir 'KevCatalog.txt'
                    $nowUtc  = [DateTime]::UtcNow

                    # ---- WPT fleet snapshot: newest CSV = latest point; stuck = pending in
                    #      >=3 consecutive newest snapshots (mirrors Get-WptTrendData semantics).
                    $snap = @{ present = $false }
                    try {
                        if (Test-Path -LiteralPath $snapDir) {
                            $files = @(Get-ChildItem -LiteralPath $snapDir -Filter 'wpt-bulkscan_*.csv' -File -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
                            if ($files.Count -gt 0) {
                                $foundCount = $files.Count
                                if ($files.Count -gt 60) { $files = @($files[0..59]) }
                                $pendSets = New-Object System.Collections.ArrayList
                                $latest = $null
                                foreach ($f in $files) {
                                    $rows = $null
                                    try { $rows = @(Import-Csv -LiteralPath $f.FullName -ErrorAction Stop) } catch { continue }
                                    $total = 0; $online = 0; $pending = 0; $reboot = 0; $stamp = ''
                                    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                                    foreach ($r in $rows) {
                                        $total++
                                        if ([string]::IsNullOrWhiteSpace($stamp)) { $stamp = [string]$r.ScanStamp }
                                        $isOn = (([string]$r.Online) -match '^(?i:true|1|yes)$')
                                        if ($isOn) { $online++ }
                                        $m = 0; $mOk = [int]::TryParse([string]$r.MECMUpdateCount,    [ref]$m)
                                        $w = 0; $wOk = [int]::TryParse([string]$r.WindowsUpdateCount, [ref]$w)
                                        $a = 0; $aOk = [int]::TryParse([string]$r.AppUpdateCount,     [ref]$a)
                                        $sum = $m + $w + $a
                                        $hn = ([string]$r.Host).Trim()
                                        # online host whose count did not parse is UNKNOWN -> keep pending
                                        $hasErr = ($isOn -and -not ($mOk -and $wOk -and $aOk))
                                        if ($hn -and ($sum -gt 0 -or $hasErr)) { $pending++; [void]$set.Add($hn) }
                                        if (([string]$r.RebootPending) -match '^(?i:true|1|yes)$') { $reboot++ }
                                    }
                                    [void]$pendSets.Add($set)
                                    if ($null -eq $latest) { $latest = @{ total = $total; online = $online; pending = $pending; reboot = $reboot; stamp = $stamp; mtime = $f.LastWriteTimeUtc } }
                                }
                                if ($null -ne $latest) {
                                    $ever = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                                    foreach ($s in $pendSets) { foreach ($h in $s) { [void]$ever.Add($h) } }
                                    $stuck = 0
                                    foreach ($h in $ever) { $streak = 0; foreach ($s in $pendSets) { if ($s.Contains($h)) { $streak++ } else { break } }; if ($streak -ge 3) { $stuck++ } }
                                    $ageH = [math]::Round(($nowUtc - $latest.mtime).TotalHours, 1); if ($ageH -lt 0) { $ageH = 0 }
                                    $snap = @{ present = $true; snapshots = $foundCount; total = $latest.total; online = $latest.online; pending = $latest.pending; reboot = $latest.reboot; stuck = $stuck; stamp = [string]$latest.stamp; ageHours = $ageH }
                                }
                            }
                        }
                    } catch {}

                    # ---- SLA firstSeen ledger (size / severity / kev / oldest age + aging buckets) ----
                    # Aging buckets classify each open finding against its SLA window
                    # (kev overrides severity; windows read from JanetLocal\sla-baseline.json
                    # with the same embedded defaults reports.psm1 uses). dueIn = deadline -
                    # age: overdue (<0), due-soon (<= 25% of the window, min 3d), else on-track.
                    $slaWin = @{ kev = 7; critical = 21; high = 30; medium = 90; low = 180 }
                    try {
                        $blPath = Join-Path $jlDir 'sla-baseline.json'
                        if (Test-Path -LiteralPath $blPath) {
                            $blRaw = Get-Content -LiteralPath $blPath -Raw -ErrorAction Stop
                            if ($blRaw -and $blRaw.Length -gt 0 -and [int]$blRaw[0] -eq 0xFEFF) { $blRaw = $blRaw.Substring(1) }
                            if (-not [string]::IsNullOrWhiteSpace($blRaw)) {
                                $blObj = $blRaw | ConvertFrom-Json -ErrorAction Stop
                                foreach ($k in @('kev','critical','high','medium','low')) {
                                    if ($blObj.PSObject.Properties[$k]) { $n = 0; if ([int]::TryParse([string]$blObj.$k, [ref]$n) -and $n -gt 0) { $slaWin[$k] = $n } }
                                }
                            }
                        }
                    } catch {}
                    $slaDeadline = {
                        param($sevKey, $isKev)
                        if ($isKev) { return [int]$slaWin.kev }
                        switch ($sevKey) { 'crit' { $slaWin.critical } 'high' { $slaWin.high } 'med' { $slaWin.medium } 'low' { $slaWin.low } default { $slaWin.medium } }
                    }
                    $sla = @{ present = $false }
                    try {
                        if (Test-Path -LiteralPath $ledPath) {
                            $raw = Get-Content -LiteralPath $ledPath -Raw -ErrorAction Stop
                            if ($null -eq $raw) { $raw = '' }
                            if ($raw.Length -gt 0 -and [int]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }  # defensive BOM strip
                            if (-not [string]::IsNullOrWhiteSpace($raw)) {
                                $obj = $null
                                try { $obj = $raw | ConvertFrom-Json -ErrorAction Stop } catch { $obj = $null }
                                if ($obj) {
                                    $count = 0; $kevc = 0; $sevCrit = 0; $sevHigh = 0; $sevMed = 0; $sevLow = 0; $sevOther = 0
                                    $overdue = 0; $dueSoon = 0; $onTrack = 0; $kevOverdue = 0
                                    $today = (Get-Date).Date
                                    $oldest = $null
                                    foreach ($prop in $obj.PSObject.Properties) {
                                        $v = $prop.Value; if ($null -eq $v) { continue }
                                        $count++
                                        $isKev = ($v.PSObject.Properties['kev'] -and [bool]$v.kev)
                                        if ($isKev) { $kevc++ }
                                        $sev = if ($v.PSObject.Properties['severity']) { ([string]$v.severity).Trim().ToLower() } else { '' }
                                        $sevKey = 'other'
                                        switch -regex ($sev) {
                                            '^(4|crit)' { $sevCrit++; $sevKey = 'crit'; break }
                                            '^(3|high)' { $sevHigh++; $sevKey = 'high'; break }
                                            '^(2|med)'  { $sevMed++;  $sevKey = 'med';  break }
                                            '^(1|low)'  { $sevLow++;  $sevKey = 'low';  break }
                                            default     { $sevOther++ }
                                        }
                                        $fs = if ($v.PSObject.Properties['firstSeen']) { [string]$v.firstSeen } else { '' }
                                        if (-not [string]::IsNullOrWhiteSpace($fs)) {
                                            $d = [DateTime]::MinValue
                                            if ([DateTime]::TryParse($fs, [ref]$d)) {
                                                if ($null -eq $oldest -or $d -lt $oldest) { $oldest = $d }
                                                $age = [int][math]::Floor(($today - $d.Date).TotalDays); if ($age -lt 0) { $age = 0 }
                                                $ddl = [int](& $slaDeadline $sevKey $isKev)
                                                $dueIn = $ddl - $age
                                                $soonBand = [math]::Max(3, [int][math]::Ceiling($ddl * 0.25))
                                                if ($dueIn -lt 0) { $overdue++; if ($isKev) { $kevOverdue++ } }
                                                elseif ($dueIn -le $soonBand) { $dueSoon++ }
                                                else { $onTrack++ }
                                            }
                                        }
                                    }
                                    $oldestAge = $null; $oldestStr = ''
                                    if ($null -ne $oldest) {
                                        $oldestAge = [int][math]::Floor(((Get-Date).Date - $oldest.Date).TotalDays); if ($oldestAge -lt 0) { $oldestAge = 0 }
                                        $oldestStr = $oldest.ToString('yyyy-MM-dd')
                                    }
                                    $sla = @{ present = $true; count = $count; kev = $kevc; critical = $sevCrit; high = $sevHigh; medium = $sevMed; low = $sevLow; other = $sevOther; oldestFirstSeen = $oldestStr; oldestAgeDays = $oldestAge; overdue = $overdue; dueSoon = $dueSoon; onTrack = $onTrack; kevOverdue = $kevOverdue }
                                }
                            }
                        }
                    } catch {}

                    # ---- KEV catalog (size + last-modified) ----
                    $kevInfo = @{ present = $false }
                    try {
                        if (Test-Path -LiteralPath $kevPath) {
                            $fi = Get-Item -LiteralPath $kevPath -ErrorAction Stop
                            $kraw = Get-Content -LiteralPath $kevPath -Raw -ErrorAction Stop
                            if ($null -eq $kraw) { $kraw = '' }
                            if ($kraw.Length -gt 0 -and [int]$kraw[0] -eq 0xFEFF) { $kraw = $kraw.Substring(1) }
                            $kset = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                            foreach ($tok in ($kraw -split '[\r\n,;\t ]+')) { $c = ([string]$tok).Trim(); if ($c -match '^(?i:CVE-\d{4}-\d{4,})$') { [void]$kset.Add($c) } }
                            $kAgeD = [int][math]::Floor(($nowUtc - $fi.LastWriteTimeUtc).TotalDays); if ($kAgeD -lt 0) { $kAgeD = 0 }
                            $kevInfo = @{ present = $true; count = $kset.Count; modified = $fi.LastWriteTime.ToString('yyyy-MM-dd HH:mm'); ageDays = $kAgeD }
                        }
                    } catch {}

                    & $writeJson $resp @{ ok = $true; snapshot = $snap; sla = $sla; kev = $kevInfo }
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
                    & $writeJson $resp @{ ok=$true; hostsTouched=$state.LogCtx.Hosts.Count; vulnsPatched=$state.LogCtx.Vulns; runCount=$state.LogCtx.RunCount; failures=$state.LogCtx.Failures }
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
                    $fname = 'upload.dat'
                    $fnameRaw = $req.Headers['X-Janet-Filename']
                    if ($fnameRaw) { try { $fname = [System.Uri]::UnescapeDataString($fnameRaw) } catch { $fname = [string]$fnameRaw } }
                    $fname = Split-Path -Leaf $fname              # base name only (no traversal)
                    foreach ($ch in [System.IO.Path]::GetInvalidFileNameChars()) { $fname = $fname.Replace($ch, '_') }
                    if ([string]::IsNullOrWhiteSpace($fname) -or $fname -eq '.' -or $fname -eq '..') { $fname = 'upload.dat' }
                    # Windows reserved device names (CON, PRN, COM1...) would target a device, not a file.
                    $stem = [System.IO.Path]::GetFileNameWithoutExtension($fname)
                    if ($stem -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') { $fname = '_' + $fname }
                    # Optional X-Janet-Subdir lets a caller co-locate related files in
                    # ONE folder (e.g. the Log4j browse uploads api+core jars together so
                    # an engine that wants a folder of jars works). Sanitized hard to a
                    # bare name (no separators / traversal); anything else -> fresh GUID.
                    $subRaw = $req.Headers['X-Janet-Subdir']
                    $subShared = $false
                    if ($subRaw -and ($subRaw -match '\A[A-Za-z0-9_-]{1,32}\z') -and ($subRaw -notmatch '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$')) { $subName = $subRaw; $subShared = $true }
                    else { $subName = [guid]::NewGuid().ToString('N').Substring(0,8) }
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

                    # Server-side session gate: a DESTRUCTIVE (state-changing) action
                    # requires an admin session = responsibility ack (POST /session/start)
                    # AND a set credential. Read-only actions (scans/queries/adsearch) are
                    # always allowed, so the AD-search bypass and read-only diagnostics
                    # still work without an admin session. This backstops the browser gate.
                    $actObj = $null; if ($mani -and $mani.actions) { $actObj = $mani.actions | Where-Object { $_.id -eq $actId } | Select-Object -First 1 }
                    # Destructive if the manifest says so, OR if this is an ACAS by-id
                    # state-changing action (absent from the manifest, so $actObj is null
                    # and the manifest test alone would default-allow it - audit#1).
                    $isDestructive = ($actObj -and $actObj.destructive) -or ($toolId -eq 'acas' -and $acasByIdDestructive -contains $actId)
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
                            $hostTouchingTool = @('wpt','acas','pkginstall','winupgrade','upr','secureboot','restart','message') -contains $toolId
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
        # Stop + dispose the off-hours scheduler poller runspace so a Ctrl+C leaves no
        # orphan poller behind: an orphan keeps polling with a now-stale token, 403s the
        # gated fire route, and stamps armed schedules blocked/error - racing a relaunched
        # server for the same files.
        if ($state.SchedPoller) {
            try { $state.SchedPoller.Ps.Stop() } catch {}
            try { $state.SchedPoller.Ps.Dispose() } catch {}
            try { $state.SchedPoller.Rs.Dispose() } catch {}
        }
        foreach ($slot in $state.ToolRunspaces.Values) { try { $slot.RS.Close(); $slot.RS.Dispose() } catch {} }
        try { $listener.Stop(); $listener.Close() } catch {}
        Write-Host "  JANET Web stopped." -ForegroundColor DarkGray
    }
}
