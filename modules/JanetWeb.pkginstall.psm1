# =============================================================================
#  JanetWeb.pkginstall.psm1  -  Remote Package Installer engine for JANET Web
#  (Re-forked for JANET Web from the proven JANET ONE engine; cross-checked vs the desktop tool + ui-spec.)
#
#  Ported from Tools\RemotePackageInstaller.ps1 (v2.5.4) engine reused, WinForms
#  layer dropped. Deploys software packages (PSADT Deploy-Application.ps1) OR raw
#  MSI bundles to remote workstations via UNC C$ share copy + WinRM Invoke-Command,
#  fanned out across many hosts in parallel with a TCP reachability probe, an
#  inline WinRM-via-DCOM bootstrap repair, per-host exit-code parsing, and live
#  per-host streaming.
#
#  v2.5.7 reachability also probes WinRM HTTPS 5986 (after HTTP 5985, before the
#  SMB/DCOM repair fallback), auto-switching that host's session to -UseSSL.
#
#  Contract:
#    Get-JanetToolManifest                          -> tool + action descriptors
#    Invoke-JanetToolAction -ActionId -Params -Credential -Emit  -> { rows; summary }
#  -Emit event shapes consumed by the UI: status / progress / row / log / audit.
# =============================================================================

# loop73: shared error->actionable-hint mapper (why a host failed + how to fix it).
Import-Module (Join-Path $PSScriptRoot 'JanetWeb.troubleshoot.psm1') -Force -ErrorAction SilentlyContinue

function Get-JanetToolManifest {
    @{
        id       = 'pkginstall'
        name     = 'Remote Package Installer'
        version  = '2.5.13'
        category = 'Patching'
        summary  = 'Deploy PSADT packages or MSI bundles to many workstations in parallel over WinRM, with WinRM-via-DCOM repair and per-host status streaming.'
        actions  = @(
            @{
                id          = 'deploy-psadt'
                label       = 'Deploy PSADT Package'
                description  = 'Copy a package folder to each target and run Deploy-Application.ps1 -DeployMode NonInteractive over WinRM, in parallel.'
                kind         = 'stream-table'
                destructive  = $true
                columns      = @('Host','Status','Detail','ExitCode','Time')
                inputs       = @(
                    @{ name='targets';     label='Targets (one host per line)';            type='hostlist'; required=$true },
                    @{ name='packagePath'; label='Package'; type='select'; optionsFrom='pkginstall-packages'; optionsArg='psadt'; required=$false; help='Pick a package (each is a folder with a Deploy-Application.ps1 (PSADT v3) or Invoke-AppDeployToolkit.ps1 (v4) dropped in the Packages folder shown below). Click the refresh button after adding new ones.' },
                    @{ name='packagePathManual'; label='...or a custom package path (UNC/local)'; type='text'; required=$false },
                    @{ name='packageName'; label='Package name (audit/display; blank = folder name)'; type='text'; required=$false },
                    @{ name='threads';     label='Parallel hosts';                          type='int';      required=$false; default=8 },
                    @{ name='installTimeoutMin'; label='Per-host install timeout (min)';     type='int';      required=$false; default=30 },
                    @{ name='confirm';     label='Type DEPLOY to arm';                     type='text';     required=$true }
                )
            },
            @{
                id          = 'deploy-msi-bundle'
                label       = 'Deploy MSI Bundle'
                description  = 'Copy selected .msi files from a bundle folder to each target and run msiexec /i per MSI with /L*v logging, in parallel.'
                kind         = 'stream-table'
                destructive  = $true
                columns      = @('Host','Status','Detail','ExitCode','Time')
                inputs       = @(
                    @{ name='targets';     label='Targets (one host per line)';     type='hostlist'; required=$true },
                    @{ name='packagePath'; label='MSI bundle'; type='select'; optionsFrom='pkginstall-packages'; optionsArg='msi'; required=$false; help='Pick a bundle (a folder of .msi files dropped in the Packages folder shown below). Click the refresh button after adding new ones.' },
                    @{ name='packagePathManual'; label='...or a custom bundle path (UNC/local)'; type='text'; required=$false },
                    @{ name='packageName'; label='Package name (audit/display; blank = folder name)';    type='text';     required=$false },
                    @{ name='msiList';     label='MSIs to install'; type='msi-checklist'; dependsOn='packagePath'; required=$false; help='Pick a bundle above, then check the .msi files to install (all checked by default; uncheck any to skip).' },
                    @{ name='msiArgs';     label='msiexec arguments'; type='text';     required=$false; default='/qn /norestart' },
                    @{ name='threads';     label='Parallel hosts';                  type='int';      required=$false; default=8 },
                    @{ name='installTimeoutMin'; label='Per-host install timeout (min)'; type='int';      required=$false; default=30 },
                    @{ name='confirm';     label='Type DEPLOY to arm';              type='text';     required=$true }
                )
            }
        )
    }
}

function ConvertTo-JanetHostList {
    # Split a pasted blob into clean, unique, upper-cased hostnames.
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return @() }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $out  = New-Object System.Collections.ArrayList
    foreach ($tok in ($Raw -split '[\r\n,;\t ]+')) {
        $h = $tok.Trim()
        if ($h -and $seen.Add($h)) { [void]$out.Add($h.ToUpperInvariant()) }
    }
    return $out.ToArray()
}

function Test-JanetTargetToken {
    # A target must be either a strict DNS-ish hostname OR a literal IP address.
    # This stops a pasted UNC fragment ('\\srv\c$'), account-qualified name
    # ('DOM\host'), forward slash, or other stray punctuation from flowing into
    # New-PSDrive \\$Computer\C$ / New-CimSession / New-PSSession and mis-targeting.
    param([string]$Token)
    if ([string]::IsNullOrWhiteSpace($Token)) { return $false }
    # Accept IPv4 literals. Reject IPv6 literals: a raw IPv6 literal would build a
    # malformed UNC (\\<ipv6>\C$) for New-PSDrive -- Windows requires the
    # ipv6-literal.net form, so a raw literal mis-targets / fails rather than
    # reaching the host. Reject it at the gate (operator gets a clean 'Rejected'
    # row) instead of attempting a broken copy. IPv6 literals never match the
    # hostname regex below either (colons), so this is the only path that let
    # them through.
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($Token, [ref]$ip)) {
        return ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork)
    }
    return ($Token -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$')
}

# Dispatcher identity + self-guard (loop10 self-guard-coverage audit). deploy-psadt
# / deploy-msi-bundle install a package (PSADT Deploy-Application.ps1 / msiexec /i)
# on every target; the wrong-box guard does NOT cover the dispatcher (self is
# dialed by its own correct name -> no COMPUTERNAME mismatch), so without this an
# operator wave that includes the JANET host would install arbitrary software on
# the dispatcher (and a package can reboot it). Mirrors the c2c/upr/remoteadmin
# identity set: name/FQDN/loopback + every bound NIC IPv4 (DNS-miss-proof).
function Get-PkgInstallLocalIdentity {
    if ($script:PkgInstallLocalIdentity) { return ,$script:PkgInstallLocalIdentity }
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($n in @($env:COMPUTERNAME, 'localhost', '127.0.0.1', '::1')) { if ($n) { [void]$set.Add($n) } }
    try { [void]$set.Add([System.Net.Dns]::GetHostName()) } catch {}
    try { $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName; if ($fqdn) { [void]$set.Add($fqdn); [void]$set.Add(($fqdn -split '\.')[0]) } } catch {}
    try { foreach ($ip in [System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME)) { [void]$set.Add($ip.IPAddressToString) } } catch {}
    try {
        foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($nic.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up) { continue }
            foreach ($ua in $nic.GetIPProperties().UnicastAddresses) {
                if ($ua.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { [void]$set.Add($ua.Address.IPAddressToString) }
            }
        }
    } catch {}
    $script:PkgInstallLocalIdentity = $set
    return ,$set
}

# True if a target token names this dispatcher host (short/FQDN/IP/loopback).
function Test-PkgInstallHostIsSelf {
    param([string]$Target)
    if ([string]::IsNullOrWhiteSpace($Target)) { return $false }
    $self = Get-PkgInstallLocalIdentity
    if ($self.Contains($Target)) { return $true }
    if ($Target -match '^127\.') { return $true }
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Target, [ref]$ip)) {
        if ($self.Contains(($Target -split '\.')[0])) { return $true }
    }
    return $false
}

# audit 2026-07-23: ONE internal single-pass split shared by ConvertTo-JanetMsiList
# and Get-JanetMsiListDropped, so the keep/drop predicate can never drift between
# them (it was duplicated - and inverted by hand - in each). An entry is DROPPED
# when it is a rooted path (C:\, \, \\server) or carries any '..' segment: each
# entry MUST stay inside the bundle, otherwise a pasted '..\..\Windows\System32\x.msi'
# would read outside $PkgPath and write outside the target's staging dir. Subdir
# entries like 'x64\foo.msi' are kept. Returns @{ Kept = [string[]]; Dropped = [string[]] }.
function Split-JanetMsiListEntries {
    param([string]$Raw)
    $kept    = New-Object System.Collections.ArrayList
    $dropped = New-Object System.Collections.ArrayList
    if (-not [string]::IsNullOrWhiteSpace($Raw)) {
        foreach ($entry in ($Raw -split '[\r\n]+')) {
            $e = $entry.Trim()
            if (-not $e) { continue }
            if ([System.IO.Path]::IsPathRooted($e) -or ($e -match '(^|[\\/])\.\.([\\/]|$)')) { [void]$dropped.Add($e) }
            else { [void]$kept.Add($e) }
        }
    }
    @{ Kept = @($kept.ToArray()); Dropped = @($dropped.ToArray()) }
}

function ConvertTo-JanetMsiList {
    # Split a pasted blob into relative MSI paths (one per line). Preserves
    # subdir entries like 'x64\foo.msi'. Returns @() when blank (caller then
    # falls back to discovering *.msi recursively under the bundle folder).
    # Predicate lives in Split-JanetMsiListEntries (audit 2026-07-23).
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return @() }
    @((Split-JanetMsiListEntries -Raw $Raw).Kept)
}

function Get-JanetMsiListDropped {
    # loop63 (item70): the INVERSE of ConvertTo-JanetMsiList - the non-blank entries it silently drops
    # (rooted path or '..' traversal). The caller warns per dropped entry so a partial selection isn't
    # reported as a clean "All N succeeded", and REFUSES a non-blank selection that dropped to empty so
    # an all-invalid list can't silently escalate to the install-EVERY-*.msi fallback. Blank -> @() (the
    # intentional install-everything path stays). Shares Split-JanetMsiListEntries' single-pass
    # predicate with ConvertTo-JanetMsiList (audit 2026-07-23) - in sync by construction.
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return @() }
    @((Split-JanetMsiListEntries -Raw $Raw).Dropped)
}

# Per-host scriptblock. Runs inside an isolated runspace -- NO outer-scope vars
# are visible. Everything it needs comes via .AddArgument(). Lifted verbatim
# (engine logic preserved) from Tools\RemotePackageInstaller.ps1 v2.5.4
# $script:RpiDeployHostScript (line 2810). The WinForms ConcurrentQueue
# 'step' push is replaced by a thread-safe step queue passed in so the harvest
# loop can stream live phase rows. Returns a [pscustomobject] result.
$script:RpiDeployHostScript = {
    param(
        [string]$Computer,
        [string]$PkgPath,
        [string]$PkgName,
        [System.Management.Automation.PSCredential]$Credential,
        $WSManOpt,
        $WSManOptSsl,
        $StepQueue,
        [string]$Mode = 'PSADT',
        [string[]]$MsiList = @(),
        [string]$MsiArgs = '/qn /norestart',
        $PathMap,
        $UseSslMap
    )

    $pushStep = {
        param([string]$Step, [string]$Detail = '')
        if ($StepQueue) {
            [void]$StepQueue.Enqueue([pscustomobject]@{
                Hostname = $Computer
                Step     = $Step
                Detail   = $Detail
            })
        }
    }

    $r = [pscustomobject]@{
        Hostname        = $Computer
        Status          = 'Failed'
        Reason          = ''
        Detail          = ''
        ExitCode        = $null
        Output          = ''
        Package         = $PkgName
        RepairAttempted = $false
        RepairSucceeded = $false
        StartTime       = (Get-Date)
        EndTime         = $null
    }

    $driveName       = "JANET_$($Computer -replace '[^a-zA-Z0-9]','')"
    $session         = $null
    $remoteSharePath = $null

    # Wrong-box guard (P2-6a): the box that answers the remote Invoke-Command
    # block below is checked against the hostname we DIALED before the
    # installer runs -- stale DNS / a reused IP could otherwise hand this
    # install to the wrong machine. IP-literal targets have no DNS indirection
    # (the box answering at that IP IS the box) and their first dot-token
    # ('192') can never equal a COMPUTERNAME, so pass '' to skip the guard.
    $expectedName = if ($Computer -match '^\d{1,3}(\.\d{1,3}){3}$') { '' } else { ($Computer -split '\.')[0] }

    try {
        ## 1. Probe WinRM: 5985 (HTTP, preferred), then 5986 (HTTPS backup).
        ## Inlined because the runspace can't see Test-RpiReachable from outer
        ## scope. $useSsl is set ONLY when 5985 is closed and 5986 answers, so
        ## the session below (step 4) dials HTTPS for an SSL-only host.
        & $pushStep 'Probing' 'TCP probe 5985/5986'
        $winrmOpen = $false
        $useSsl    = $false
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, 5985, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) {
                $winrmOpen = $true; $tc.Close()
            }
        } catch {}
        finally { if ($tc) { try { $tc.Close() } catch {} } }

        if (-not $winrmOpen) {
            ## 1a. WinRM 5985 (HTTP) closed -- try 5986 (HTTPS) before falling
            ## back to the SMB/DCOM repair path.
            $tc = $null
            try {
                $tc = New-Object System.Net.Sockets.TcpClient
                $iar = $tc.BeginConnect($Computer, 5986, $null, $null)
                if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) {
                    $winrmOpen = $true; $useSsl = $true; $tc.Close()
                }
            } catch {}
            finally { if ($tc) { try { $tc.Close() } catch {} } }
        }

        if (-not $winrmOpen) {
            ## 1b. WinRM closed (5985 and 5986). Probe SMB (445) -- if THAT's
            ## open we have a DCOM-repair side-channel.
            $smbOpen = $false
            $tc = $null
            try {
                $tc = New-Object System.Net.Sockets.TcpClient
                $iar = $tc.BeginConnect($Computer, 445, $null, $null)
                if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) {
                    $smbOpen = $true; $tc.Close()
                }
            } catch {}
            finally { if ($tc) { try { $tc.Close() } catch {} } }

            if (-not $smbOpen) {
                $r.Reason = 'Machine is offline or unreachable (no TCP on 5985, 5986 or 445)'
                return $r
            }

            ## 1c. SMB open + WinRM closed -> attempt DCOM bootstrap of WinRM.
            ## Two-attempt CIM connect, then ChangeStartMode + StartService +
            ## winrm quickconfig (with -skipNetworkProfileCheck), then re-probe
            ## 5985 with a 30s budget. Requires a credential for the DCOM session.
            ## (quickconfig provisions the HTTP listener only, so the re-probe
            ## stays 5985 -- 5986 needs a cert quickconfig does not create.)
            & $pushStep 'Repairing' 'DCOM bootstrap of WinRM'
            $r.RepairAttempted = $true
            if (-not $Credential) {
                $r.Reason = 'WinRM closed; DCOM repair requires a credential but none was supplied'
                return $r
            }
            $opt = New-CimSessionOption -Protocol DCOM
            $cim = $null
            for ($attempt = 1; $attempt -le 2 -and -not $cim; $attempt++) {
                try {
                    $cim = New-CimSession -ComputerName $Computer -Credential $Credential -SessionOption $opt -OperationTimeoutSec 30 -ErrorAction Stop
                } catch {
                    if ($attempt -lt 2) { Start-Sleep -Seconds 2 }
                }
            }
            if (-not $cim) {
                $r.Reason = 'WinRM closed; DCOM repair connect failed (port 135 unreachable or RPC blocked)'
                return $r
            }
            try {
                $svc = Get-CimInstance -CimSession $cim -ClassName Win32_Service -Filter "Name='WinRM'" -ErrorAction Stop
                if ($svc.StartMode -ne 'Auto') {
                    try { Invoke-CimMethod -CimSession $cim -InputObject $svc -MethodName ChangeStartMode -Arguments @{ StartMode = 'Automatic' } -ErrorAction Stop | Out-Null } catch {}
                }
                if ($svc.State -ne 'Running') {
                    try { Invoke-CimMethod -CimSession $cim -InputObject $svc -MethodName StartService -ErrorAction Stop | Out-Null } catch {}
                    Start-Sleep -Seconds 2
                }
                $cmd = 'cmd.exe /c winrm quickconfig -force -quiet -skipNetworkProfileCheck >C:\Windows\Temp\rpi_winrm_repair.log 2>&1'
                try { Invoke-CimMethod -CimSession $cim -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd } -ErrorAction Stop | Out-Null } catch {}
                Start-Sleep -Seconds 3

                $deadline = (Get-Date).AddSeconds(30)
                do {
                    $tc = $null
                    try {
                        $tc = New-Object System.Net.Sockets.TcpClient
                        $iar = $tc.BeginConnect($Computer, 5985, $null, $null)
                        if ($iar.AsyncWaitHandle.WaitOne(2000, $false) -and $tc.Connected) {
                            $winrmOpen = $true; $tc.Close()
                        }
                    } catch {}
                    finally { if ($tc) { try { $tc.Close() } catch {} } }
                    if (-not $winrmOpen -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 2 }
                } while (-not $winrmOpen -and (Get-Date) -lt $deadline)

                if ($winrmOpen) {
                    $r.RepairSucceeded = $true
                } else {
                    $r.Reason = 'WinRM still closed after 30s post-repair probe; DCOM bootstrap did not take'
                    return $r
                }
            } catch {
                $r.Reason = "DCOM repair error: $($_.Exception.Message)"
                return $r
            } finally {
                try { Remove-CimSession -CimSession $cim -ErrorAction SilentlyContinue } catch {}
            }
        }

        ## 2. Mount C$ admin share. When a credential is supplied we mount with
        ## it; otherwise rely on the server process's current identity.
        & $pushStep 'Copying' 'Mounting C$ + copying package'
        if (Get-PSDrive -Name $driveName -EA SilentlyContinue) {
            Remove-PSDrive -Name $driveName -Force -EA SilentlyContinue
        }
        if ($Credential) {
            New-PSDrive -Name $driveName -PSProvider FileSystem -Root "\\$Computer\C`$" -Credential $Credential -EA Stop | Out-Null
        } else {
            New-PSDrive -Name $driveName -PSProvider FileSystem -Root "\\$Computer\C`$" -EA Stop | Out-Null
        }

        $remoteBase = "${driveName}:\Temp"
        if (-not (Test-Path $remoteBase)) {
            New-Item -ItemType Directory -Force -Path $remoteBase | Out-Null
        }

        ## 3. Copy package to the target's C:\Temp\<pkg>_<stamp>\.
        ## PSADT mode: copy the whole folder (Deploy-Application.ps1 needs its
        ## siblings). MSI mode with a selection: copy ONLY the selected .msi
        ## files (preserving any 1-level subdir like x64\foo.msi). MSI mode with
        ## an EMPTY selection: copy the whole bundle folder so the remote
        ## *.msi discovery fallback finds real files (install-everything).
        $stamp            = Get-Date -Format 'yyyyMMddHHmmss'
        $safePkgName      = ($PkgName -replace '[^a-zA-Z0-9._-]','_')
        if ([string]::IsNullOrWhiteSpace($safePkgName)) { $safePkgName = 'pkg' }
        $remoteFolderName = "${safePkgName}_$stamp"
        $remoteSharePath  = Join-Path $remoteBase $remoteFolderName
        $remoteLocalPath  = "C:\Temp\$remoteFolderName"
        # Publish the on-target staged path so the driver can sweep it if the
        # wall-clock watchdog or an operator-cancel abandons this host (its
        # finally cleanup below never runs in that case, leaking the copy).
        # Publish $useSsl alongside it so a post-loop cleanup sweep (below,
        # driver-side) dials an SSL-only host over HTTPS too.
        if ($PathMap) { $PathMap[$Computer] = $remoteLocalPath }
        if ($UseSslMap) { $UseSslMap[$Computer] = $useSsl }

        if ($Mode -eq 'MSI' -and @($MsiList).Count -gt 0) {
            New-Item -ItemType Directory -Force -Path $remoteSharePath -EA Stop | Out-Null
            foreach ($rel in $MsiList) {
                $srcFile = Join-Path $PkgPath $rel
                if (-not (Test-Path -LiteralPath $srcFile)) {
                    ## Don't fail the whole host yet -- the per-MSI loop on the
                    ## remote flags this as 'MSI not found in copied bundle'.
                    continue
                }
                $dstFile = Join-Path $remoteSharePath $rel
                $dstDir  = Split-Path $dstFile -Parent
                if (-not (Test-Path -LiteralPath $dstDir)) {
                    New-Item -ItemType Directory -Force -Path $dstDir -EA Stop | Out-Null
                }
                Copy-Item -LiteralPath $srcFile -Destination $dstFile -Force -EA Stop
                ## Post-copy integrity: a truncated/corrupt copy over a flaky
                ## SMB link would otherwise be handed straight to msiexec.
                ## Compare source vs destination LENGTH (cheap) then SHA256
                ## before Unblock-File/msiexec; on mismatch fail this host with a
                ## clear row instead of executing a bad installer.
                $srcInfo = Get-Item -LiteralPath $srcFile -EA Stop
                $dstInfo = Get-Item -LiteralPath $dstFile -EA Stop
                if ($srcInfo.Length -ne $dstInfo.Length) {
                    $r.Reason = "Copy verification failed for '$rel': size mismatch (source $($srcInfo.Length) B, copy $($dstInfo.Length) B)"
                    $r.Detail = $r.Reason
                    return $r
                }
                $srcHash = (Get-FileHash -LiteralPath $srcFile -Algorithm SHA256 -EA Stop).Hash
                $dstHash = (Get-FileHash -LiteralPath $dstFile -Algorithm SHA256 -EA Stop).Hash
                if ($srcHash -ne $dstHash) {
                    $r.Reason = "Copy verification failed for '$rel': SHA256 mismatch (source $srcHash, copy $dstHash)"
                    $r.Detail = $r.Reason
                    return $r
                }
            }
        } else {
            Copy-Item -Path $PkgPath -Destination $remoteSharePath -Recurse -Force -EA Stop
            ## Post-copy integrity (folder path): a per-file hash over a large
            ## PSADT tree is too costly, so compare file COUNT and total byte
            ## SIZE of the source vs the copied tree before executing; on
            ## mismatch fail this host instead of running a partial package.
            $srcFiles = @(Get-ChildItem -LiteralPath $PkgPath -Recurse -File -EA Stop)
            $dstFiles = @(Get-ChildItem -LiteralPath $remoteSharePath -Recurse -File -EA Stop)
            $srcBytes = ($srcFiles | Measure-Object -Property Length -Sum).Sum
            $dstBytes = ($dstFiles | Measure-Object -Property Length -Sum).Sum
            if ($srcFiles.Count -ne $dstFiles.Count -or $srcBytes -ne $dstBytes) {
                $r.Reason = "Copy verification failed: tree mismatch (source $($srcFiles.Count) file(s)/$srcBytes B, copy $($dstFiles.Count) file(s)/$dstBytes B)"
                $r.Detail = $r.Reason
                return $r
            }
        }

        ## 4. Open WinRM session and run the package (mode-dependent).
        if ($Mode -eq 'MSI') {
            if (@($MsiList).Count -gt 0) {
                & $pushStep 'Deploying' "Running $($MsiList.Count) MSI(s) via msiexec"
            } else {
                & $pushStep 'Deploying' 'Running every bundle MSI via msiexec'
            }
        } else {
            & $pushStep 'Deploying' 'Running the PSADT deploy script'
        }
        ## -UseSSL only when the probe found the host reachable ONLY on 5986
        ## (WSManOptSsl carries SkipCACheck/SkipCNCheck for the common
        ## self-signed WinRM HTTPS cert; port 5986 is implicit).
        $sessOpt = if ($useSsl) { $WSManOptSsl } else { $WSManOpt }
        $sessSplat = @{ ComputerName=$Computer; Authentication='Negotiate'; SessionOption=$sessOpt; ErrorAction='Stop' }
        if ($Credential) { $sessSplat['Credential'] = $Credential }
        if ($useSsl) { $sessSplat['UseSSL'] = $true }
        $session = New-PSSession @sessSplat

        if ($Mode -eq 'MSI') {
            ## MSI bundle mode. For each selected MSI (filename relative to the
            ## copied bundle root), shell `msiexec /i <full> $MsiArgs /L*v <log>`
            ## on the remote and capture per-MSI exit codes. Host aggregate Status
            ## is Success only when EVERY MSI returned a success exit (0/1641/3010).
            $invokeResult = Invoke-Command -Session $session -ArgumentList $remoteLocalPath, $MsiList, $MsiArgs, $expectedName -ScriptBlock {
                param($destPath, $msiList, $msiArgs, $expected)
                $res = [pscustomobject]@{
                    Status   = 'Failed'
                    ExitCode = $null
                    Reason   = ''
                    Output   = ''
                }
                # Wrong-box guard (HARD ABORT): the box that answered runs this block,
                # so $env:COMPUTERNAME IS the real machine. If it isn't the one we
                # dialed (stale DNS / reused IP), abort before any msiexec runs.
                if ($expected -and ($env:COMPUTERNAME.Trim().ToUpper() -ne ([string]$expected).Trim().ToUpper())) {
                    $res.Reason = "wrong box: dialed '$expected', answered '$($env:COMPUTERNAME)' - ABORTED, no install run"
                    return $res
                }
                try {
                    Get-ChildItem -Path $destPath -Filter *.msi -Recurse -EA SilentlyContinue | Unblock-File
                    ## When the operator supplied no explicit MSI list, install
                    ## every *.msi discovered (recursive) in the copied bundle.
                    if (-not $msiList -or @($msiList).Count -eq 0) {
                        $msiList = @(Get-ChildItem -Path $destPath -Filter *.msi -Recurse -File -EA SilentlyContinue |
                            ForEach-Object { $_.FullName.Substring($destPath.Length).TrimStart('\') })
                    }
                    $perMsi        = New-Object System.Collections.Generic.List[pscustomobject]
                    $sb            = New-Object System.Text.StringBuilder
                    $sawRebootInit = $false
                    $sawReboot     = $false
                    $firstFailMsi  = $null
                    $firstFailExit = $null

                    foreach ($rel in $msiList) {
                        $full = Join-Path $destPath $rel
                        $leaf = [System.IO.Path]::GetFileNameWithoutExtension($rel)
                        $logFile = Join-Path $destPath ($leaf + '.msiexec.log')
                        if (-not (Test-Path -LiteralPath $full)) {
                            $perMsi.Add([pscustomobject]@{ Msi=$rel; ExitCode=$null; Status='Failed'; Reason='MSI not found in copied bundle' })
                            if (-not $firstFailMsi) { $firstFailMsi = $rel }
                            [void]$sb.AppendLine("[$rel] MISSING after copy")
                            continue
                        }

                        $argList = '/i "{0}" /L*v "{1}" {2}' -f $full, $logFile, $msiArgs

                        ## Direct ProcessStartInfo + WaitForExit pattern.
                        ## Start-Process -Wait -PassThru can return ExitCode=$null
                        ## inside a remote PSSession (handle reaped early).
                        $exit = $null
                        $psi = New-Object System.Diagnostics.ProcessStartInfo
                        $psi.FileName        = "$env:SystemRoot\System32\msiexec.exe"
                        $psi.Arguments       = $argList
                        $psi.UseShellExecute = $false
                        $psi.CreateNoWindow  = $true
                        $proc = $null
                        try {
                            $proc = [System.Diagnostics.Process]::Start($psi)
                        } catch {
                            $perMsi.Add([pscustomobject]@{ Msi=$rel; ExitCode=$null; Status='Failed'; Reason="msiexec failed to launch: $($_.Exception.Message)" })
                            if (-not $firstFailMsi) { $firstFailMsi = $rel }
                            [void]$sb.AppendLine("[$rel] LAUNCH FAILED - $($_.Exception.Message)")
                            continue
                        }
                        if ($proc) {
                            $proc.WaitForExit()
                            $exit = $proc.ExitCode
                            try { $proc.Dispose() } catch {}
                        }

                        $status = 'Failed'
                        $reason = ''
                        switch ($exit) {
                            0       { $status = 'Success'; $reason = 'Success' }
                            1641    { $status = 'Success'; $reason = 'Success (reboot initiated)'; $sawRebootInit = $true }
                            3010    { $status = 'Success'; $reason = 'Success (reboot required)';  $sawReboot = $true }
                            1602    { $status = 'Failed';  $reason = 'User cancelled (1602)' }
                            1603    { $status = 'Failed';  $reason = "Fatal install error (1603) - see $logFile" }
                            1605    { $status = 'Failed';  $reason = 'Unknown product (1605)' }
                            1618    { $status = 'Failed';  $reason = 'Another install in progress (1618)' }
                            1619    { $status = 'Failed';  $reason = 'Package open failed (1619) - corrupt or locked' }
                            1638    { $status = 'AlreadyInstalled'; $reason = 'Another version already installed (1638) - install did NOT run; installed version NOT verified compliant' }
                            default {
                                if ($null -eq $exit) { $status = 'Failed'; $reason = 'msiexec failed to launch (no exit code)' }
                                else                 { $status = 'Failed'; $reason = "msiexec exit $exit - see $logFile" }
                            }
                        }
                        $perMsi.Add([pscustomobject]@{ Msi=$rel; ExitCode=$exit; Status=$status; Reason=$reason })
                        # Only a genuine 'Failed' seeds the first-failure marker. 'AlreadyInstalled'
                        # (MSI 1638) is a distinct non-failure, non-success state and must not trip the fail path.
                        if ($status -eq 'Failed' -and -not $firstFailMsi) {
                            $firstFailMsi  = $rel
                            $firstFailExit = $exit
                        }
                        [void]$sb.AppendLine("[$rel] exit=$exit  $reason")
                    }

                    $totalCount     = $perMsi.Count
                    $successCount   = @($perMsi | Where-Object { $_.Status -eq 'Success' }).Count
                    # 1638 = another version already installed; msiexec refused, nothing changed, and the
                    # installed version was NOT verified >= the package (may still be the OLD vulnerable one).
                    # Neither success nor failure - counted here only to detect the all-1638 (nothing-installed) case.
                    $installedCount = @($perMsi | Where-Object { $_.Status -eq 'AlreadyInstalled' }).Count
                    $failCount      = @($perMsi | Where-Object { $_.Status -eq 'Failed' }).Count

                    if ($totalCount -eq 0) {
                        $res.Status = 'Failed'
                        $res.Reason = 'No MSIs to install (empty selection)'
                    } elseif ($failCount -eq 0 -and $successCount -eq 0 -and $installedCount -eq $totalCount) {
                        # loop60 (item67): EVERY MSI returned 1638 - msiexec REFUSED to install because another
                        # version is present, so NOTHING changed on the box and the installed version was NEVER
                        # verified >= the package (it may still be the OLD vulnerable one). This is NOT a patch:
                        # report AlreadyInstalled -> harvest books it Skipped/itemCount 0, never Success/VulnPatched.
                        $res.Status  = 'AlreadyInstalled'
                        $res.Reason  = "All $totalCount MSI(s): another version already installed (1638) - install did NOT run; version NOT verified compliant"
                        $res.ExitCode = 1638
                    } elseif ($failCount -eq 0) {
                        $res.Status = 'Success'
                        if     ($sawRebootInit) { $res.Reason = "All $totalCount MSI(s) succeeded (reboot initiated)"; $res.ExitCode = 1641 }
                        elseif ($sawReboot)     { $res.Reason = "All $totalCount MSI(s) succeeded (reboot required)";  $res.ExitCode = 3010 }
                        else {
                            $installedNote = if ($installedCount -gt 0) { " ($installedCount already installed, version unverified)" } else { '' }
                            $res.Reason = "All $totalCount MSI(s) succeeded$installedNote"; $res.ExitCode = 0
                        }
                    } else {
                        $firstFailReason = ''
                        $ff = $perMsi | Where-Object { $_.Msi -eq $firstFailMsi -and $_.Status -ne 'Success' } | Select-Object -First 1
                        if ($ff) { $firstFailReason = $ff.Reason }
                        $exitTag = if ($null -eq $firstFailExit) { 'no exit code' } else { "exit=$firstFailExit" }
                        $res.Status   = 'Failed'
                        $res.Reason   = "$failCount of $totalCount MSI(s) failed: $firstFailMsi ($exitTag) - $firstFailReason"
                        $res.ExitCode = $firstFailExit
                    }
                    $res.Output = $sb.ToString().TrimEnd()
                    return $res
                } catch {
                    $res.Reason = "Terminating error: $($_.Exception.Message)"
                    return $res
                }
            } -EA Stop
        } else {
            $invokeResult = Invoke-Command -Session $session -ArgumentList $remoteLocalPath, $expectedName -ScriptBlock {
                param($destPath, $expected)
                $res = [pscustomobject]@{
                    Status   = 'Failed'
                    ExitCode = $null
                    Reason   = ''
                    Output   = ''
                }
                # Wrong-box guard (HARD ABORT): the box that answered runs this block,
                # so $env:COMPUTERNAME IS the real machine. If it isn't the one we
                # dialed (stale DNS / reused IP), abort before Deploy-Application.ps1 runs.
                if ($expected -and ($env:COMPUTERNAME.Trim().ToUpper() -ne ([string]$expected).Trim().ToUpper())) {
                    $res.Reason = "wrong box: dialed '$expected', answered '$($env:COMPUTERNAME)' - ABORTED, no install run"
                    return $res
                }
                try {
                    Get-ChildItem -Path $destPath -Filter *.ps1 -Recurse -EA SilentlyContinue | Unblock-File
                    # PSADT v3 entry = Deploy-Application.ps1; v4 renamed it Invoke-AppDeployToolkit.ps1
                    # (-DeployMode NonInteractive is valid on both). v3 name first so a mixed tree
                    # keeps its historical entry point.
                    $deploy = Get-ChildItem -Path $destPath -Include 'Deploy-Application.ps1','Invoke-AppDeployToolkit.ps1' -Recurse -File -EA SilentlyContinue |
                              Sort-Object { $_.Name -ne 'Deploy-Application.ps1' } | Select-Object -First 1
                    if (-not $deploy) {
                        $res.Reason = 'Deploy-Application.ps1 / Invoke-AppDeployToolkit.ps1 (PSADT v3/v4 entry script) not found in package'
                        return $res
                    }
                    Set-Location $deploy.DirectoryName
                    # loop61 (item68): pre-seed $null, NOT 0. `& script.ps1` only updates $LASTEXITCODE if the
                    # script calls exit / Exit-Script (or ends on a native command). A deploy script that returns
                    # without setting an exit code would otherwise leave a pre-seeded 0 and masquerade as a clean
                    # exit-0 Success though nothing installed. $null is caught below and booked Failed.
                    $global:LASTEXITCODE = $null
                    $output   = & $deploy.FullName -DeployMode NonInteractive 2>&1
                    $exitCode = $LASTEXITCODE
                    $outStr   = ($output | Out-String).TrimEnd()
                    $res.Output   = $outStr
                    $res.ExitCode = $exitCode

                    # The PSADT exit code is authoritative: 0 / 1641 / 3010 = Success ;
                    # 60012 = Deferred ; else = Failed. Do NOT downgrade a success exit
                    # just because the merged 2>&1 output contains an ERROR/FAILED line -
                    # PSADT logs non-terminating error records routinely, which was
                    # flipping clean installs to Failed and writing false audit rows.
                    $successExits = @(0, 1641, 3010)
                    $softFail     = $outStr -match '(?im)^\s*(ERROR|FAILED|FAILURE)\b'
                    if ($null -eq $exitCode) {
                        # loop61 (item68): the deploy script ran to completion but set NO exit code (never
                        # called exit / Exit-Script). We cannot confirm it installed anything, so it is Failed -
                        # never a false Success/VulnPatched. (A terminating error is caught below instead.)
                        $res.Status = 'Failed'
                        $res.Reason = "$($deploy.Name) returned no exit code (never called exit / Exit-Script) - cannot confirm the install ran; treated as Failed"
                    } elseif ($successExits -contains $exitCode) {
                        $baseReason = switch ($exitCode) {
                            3010 { 'Success (reboot required)' }
                            1641 { 'Success (reboot initiated)' }
                            default { 'Success' }
                        }
                        if ($softFail) {
                            # The exit code says success, but the PSADT output carried
                            # ERROR/FAILED/FAILURE line(s) - a SOFT-FAILURE. Surface it as a
                            # DISTINCT 'Success (warnings)' status (with the offending line(s))
                            # so it is visible in the grid/audit rather than masked as a clean
                            # Success by a mere footnote. A truly clean run stays 'Success'.
                            $warnLines = @($outStr -split "`r?`n" |
                                            Where-Object { $_ -match '(?im)^\s*(ERROR|FAILED|FAILURE)\b' } |
                                            ForEach-Object { $_.Trim() } |
                                            Select-Object -First 3)
                            $warnText  = ($warnLines -join ' | ')
                            $res.Status = 'Success (warnings)'
                            $res.Reason = "$baseReason - WARNING: output had ERROR/FAILED line(s); review the log" +
                                          $(if ($warnText) { " [$warnText]" } else { '' })
                        } else {
                            $res.Status = 'Success'
                            $res.Reason = $baseReason
                        }
                    } elseif ($exitCode -eq 60012) {
                        $res.Status = 'Deferred'
                        $res.Reason = 'User deferred install (PSADT 60012)'
                    } else {
                        $res.Status = 'Failed'
                        $res.Reason = "Non-zero exit code: $exitCode"
                    }
                    return $res
                } catch {
                    $res.Reason = "Terminating error: $($_.Exception.Message)"
                    return $res
                }
            } -EA Stop
        }

        ## 5. Map invokeResult onto $r.
        $sub = $invokeResult
        if ($sub -is [System.Array]) {
            $sub = $sub | Where-Object { $_ -and $_.PSObject.Properties['Status'] } | Select-Object -First 1
        }
        if ($sub) {
            $r.Status   = $sub.Status
            $r.Reason   = $sub.Reason
            $r.ExitCode = $sub.ExitCode
            $r.Output   = $sub.Output
            $detail = $sub.Reason
            if ($null -ne $sub.ExitCode) { $detail = "$detail (exit=$($sub.ExitCode))" }
            $r.Detail = $detail
        } else {
            $r.Status = 'Failed'
            $r.Reason = 'Unknown remote error (no structured result)'
            $r.Detail = $r.Reason
        }
    } catch {
        $r.Status = 'Failed'
        $r.Reason = $_.Exception.Message
        $r.Detail = $r.Reason
    } finally {
        if ($remoteSharePath -and (Test-Path $remoteSharePath -EA SilentlyContinue)) {
            Remove-Item $remoteSharePath -Recurse -Force -EA SilentlyContinue
        }
        if ($session) { Remove-PSSession -Session $session -EA SilentlyContinue }
        Remove-PSDrive -Name $driveName -Force -EA SilentlyContinue
        $r.EndTime = (Get-Date)
    }

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

    # Operator-cancel contract: the server injects a synchronized hashtable as
    # $Params['__job']; its 'Cancel' flag (set by POST /job/<id>/cancel) lets a
    # cancelled run abort the LOCAL runspaces driving remaining hosts instead of
    # mutating every remaining host. What cancel reaches depends on phase/mode:
    # hosts never dispatched (still Queued) are untouched; for in-flight hosts
    # BeginStop stops the local pipeline AND, in PSADT mode, the stop propagates
    # into the remote Invoke-Command pipeline; the raw-msiexec path launches a
    # detached msiexec process, so an MSI already started finishes on the target.
    # No __job (defensive) -> cancelCheck is $false.
    $cancelJob = $null
    if ($Params -and $Params.ContainsKey('__job')) { $cancelJob = $Params['__job'] }
    $cancelCheck = { if ($cancelJob) { try { [bool]$cancelJob['Cancel'] } catch { $false } } else { $false } }

    if ($ActionId -ne 'deploy-psadt' -and $ActionId -ne 'deploy-msi-bundle') {
        & $send @{ type='error'; text="Unknown action '$ActionId'." }
        return @{ rows=@(); summary=@{} }
    }

    # loop62 (item69): confirm-word gate. Pushing/installing arbitrary software fleet-wide is the most
    # destructive action in the suite, yet it was the ONLY destructive tool with no typed confirm-word
    # (adto FIX/VALIDATE, secureboot ENABLE, c2c, certdeploy, winrmbridge all have one). Fail-closed,
    # server-side, BEFORE any target parsing / self-guard / fan-out: refuse unless the operator typed
    # DEPLOY (exactly). The server admin-session gate + self-guard + wrong-box + IPv4 guards remain; this
    # adds the missing typed barrier so a stray armed session can't one-click a fleet-wide install.
    if ([string]$Params['confirm'] -ne 'DEPLOY') {
        & $send @{ type='log'; level='err'; text='Refused: type DEPLOY (exactly) in Confirm to arm the deploy.' }
        return @{ rows=@(); summary=@{ total=0; rejected=$true } }
    }

    $rawTargets = ConvertTo-JanetHostList ([string]$Params['targets'])
    # Charset-validate each token before it can reach New-PSDrive / New-CimSession /
    # New-PSSession. A UNC fragment, account-qualified name, or stray backslash is
    # rejected (warn row) rather than attempted, so it can't mis-target.
    $targets = New-Object System.Collections.ArrayList
    foreach ($t in $rawTargets) {
        if (Test-JanetTargetToken $t) {
            [void]$targets.Add($t)
        } else {
            & $send @{ type='row'; Host=$t; Status='Rejected'; Detail='Invalid target (not a valid hostname or IP); skipped'; ExitCode=''; Time=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss') }
            & $send @{ type='log'; level='warn'; text="[$t] rejected: not a valid hostname or IP address" }
        }
    }
    $targets = $targets.ToArray()
    if ($targets.Count -eq 0) {
        & $send @{ type='log'; level='warn'; text='No valid targets.' }
        return @{ rows=@(); summary=@{ total=0 } }
    }

    # Self-guard (loop10): drop the JANET dispatcher host BEFORE fan-out - a deploy
    # installs software on the box it runs on otherwise. Unconditional (both deploy
    # actions always install; there is no dry-run). See Get-PkgInstallLocalIdentity.
    $selfDrop = @($targets | Where-Object { Test-PkgInstallHostIsSelf $_ })
    if ($selfDrop.Count -gt 0) {
        & $send @{ type='log'; level='warn'; text="Self-guard: dropped the JANET dispatcher host from this deploy wave ($($selfDrop -join ', ')) - pkginstall never installs on the box it runs on." }
        $targets = @($targets | Where-Object { -not (Test-PkgInstallHostIsSelf $_) })
    }
    if ($targets.Count -eq 0) {
        & $send @{ type='log'; level='warn'; text='Only target was this dispatcher host - nothing to deploy (self-guard).' }
        return @{ rows=@(); summary=@{ total=0; selfSkipped=$selfDrop.Count } }
    }

    # A custom path (UNC/local) overrides the dropdown selection when supplied.
    $pkgPath = [string]$Params['packagePath']
    $pkgManual = [string]$Params['packagePathManual']
    if (-not [string]::IsNullOrWhiteSpace($pkgManual)) { $pkgPath = $pkgManual }
    if ([string]::IsNullOrWhiteSpace($pkgPath)) {
        & $send @{ type='log'; level='warn'; text='Pick a package from the dropdown (or enter a custom package path).' }
        return @{ rows=@(); summary=@{ total=$targets.Count } }
    }
    $pkgPath = $pkgPath.Trim()
    # Pre-gate a UNC source with a TCP 445 (SMB) probe so an unreachable share
    # fast-fails instead of blocking this job on the SMB timeout. TCP, not
    # Test-Connection: AFNET GPO blocks ICMP echo, so ping reports every share
    # host down even when SMB is wide open (desktop v2.3.2 reliability port).
    if ($pkgPath -match '^\\\\([^\\]+)') {
        $shareHost = $Matches[1]
        $shareOpen = $false
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($shareHost, 445, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(2000, $false) -and $tc.Connected) { $shareOpen = $true }
        } catch {}
        finally { if ($tc) { try { $tc.Close() } catch {} } }
        if (-not $shareOpen) {
            & $send @{ type='log'; level='err'; text="Package share host unreachable (no TCP 445 within 2s): $pkgPath" }
            return @{ rows=@(); summary=@{ total=$targets.Count } }
        }
    }
    if (-not (Test-Path -LiteralPath $pkgPath)) {
        & $send @{ type='log'; level='err'; text="Package path not found or not reachable: $pkgPath" }
        return @{ rows=@(); summary=@{ total=$targets.Count } }
    }

    $mode = if ($ActionId -eq 'deploy-msi-bundle') { 'MSI' } else { 'PSADT' }

    # v2.5.3 port: in MSI mode the resolved path may point at a SINGLE .msi
    # FILE (operator pasted a direct file path). The deploy scriptblock expects
    # pkgPath = folder + msiList = relative leaves, so rewrite to
    # (parent folder, [leaf]) here.
    $singleMsiLeaf = $null
    if ($mode -eq 'MSI') {
        $pkgItem = Get-Item -LiteralPath $pkgPath -ErrorAction SilentlyContinue
        if ($pkgItem -and -not $pkgItem.PSIsContainer -and $pkgItem.Extension -ieq '.msi') {
            $singleMsiLeaf = $pkgItem.Name
            $pkgPath       = $pkgItem.DirectoryName
        }
    }

    $pkgName = [string]$Params['packageName']
    if ([string]::IsNullOrWhiteSpace($pkgName)) {
        if ($singleMsiLeaf) { $pkgName = [System.IO.Path]::GetFileNameWithoutExtension($singleMsiLeaf) }
        else                { $pkgName = Split-Path -Path $pkgPath -Leaf }
    }

    $msiList = @()
    $msiArgs = '/qn /norestart'
    if ($mode -eq 'MSI') {
        $msiList = ConvertTo-JanetMsiList ([string]$Params['msiList'])
        if ($singleMsiLeaf) {
            $msiList = @($singleMsiLeaf)
        } else {
            # loop63 (item70): surface every entry ConvertTo-JanetMsiList dropped (rooted / '..'), so a
            # partial selection isn't quietly reported as a clean "All N succeeded" for fewer MSIs; and
            # REFUSE a non-blank selection that dropped to EMPTY rather than falling through to the
            # install-EVERY-*.msi fallback (a scope escalation the operator never asked for). A blank
            # selection produces no drops and keeps the intentional install-everything path below.
            $droppedMsi = Get-JanetMsiListDropped ([string]$Params['msiList'])
            if (@($droppedMsi).Count -gt 0) {
                foreach ($d in $droppedMsi) {
                    & $send @{ type='log'; level='warn'; text="MSI entry rejected (rooted path or '..' traversal - must stay inside the bundle): $d" }
                }
                if (@($msiList).Count -eq 0) {
                    $n = @($droppedMsi).Count
                    & $send @{ type='log'; level='err'; text="All $n selected MSI entr$(if ($n -eq 1) { 'y' } else { 'ies' }) were rejected (rooted/traversal) - refusing rather than installing the whole bundle." }
                    & $send @{ type='status'; text='Aborted: every selected MSI entry was invalid (rooted/traversal).' }
                    return @{ rows=@(); summary=@{ total=$targets.Count; ok=0; failed=0; deferred=0; rejected=$true } }
                }
            }
        }
        if ([string]$Params['msiArgs']) { $msiArgs = [string]$Params['msiArgs'] }
        # $msiArgs is interpolated raw after the /i "<msi>" and /L*v "<log>" tokens.
        # An embedded double-quote would break that quoting and could re-target the
        # install path / log path, so reject it instead of silently accepting.
        if ($msiArgs -match '"') {
            & $send @{ type='log'; level='err'; text="msiexec arguments rejected: must not contain a double-quote (`") - it would break the /i and /L*v quoting." }
            & $send @{ type='status'; text='Aborted: msiexec arguments contained a double-quote.' }
            return @{ rows=@(); summary=@{ total=$targets.Count; ok=0; failed=0; deferred=0 } }
        }
    }

    # TryParse zeroes its [ref] on failure, so only adopt the value when the
    # parse succeeds; non-numeric input keeps the documented default of 8.
    $threads = 8
    if ($Params['threads']) {
        $parsedThreads = 0
        if ([int]::TryParse([string]$Params['threads'], [ref]$parsedThreads)) { $threads = $parsedThreads }
    }
    $threads = [Math]::Max(1, [Math]::Min(32, $threads))

    # Per-host install timeout. The deploy blocks the WinRM receive with NO
    # streamed output for the whole install (PSADT NonInteractive / msiexec
    # WaitForExit), so the session OperationTimeout must cover the entire install
    # or a long package (Office/Adobe/.NET/VS) trips a spurious operation-timeout
    # that surfaces as a false Failed row AND a false audit Failure even though the
    # install completed. Default 30 min; operator-sizable via the manifest input.
    # Bound 1..240 min.
    $installTimeoutMin = 30
    if ($Params['installTimeoutMin']) {
        $parsedTimeout = 0
        if ([int]::TryParse([string]$Params['installTimeoutMin'], [ref]$parsedTimeout)) { $installTimeoutMin = $parsedTimeout }
    }
    $installTimeoutMin = [Math]::Max(1, [Math]::Min(240, $installTimeoutMin))
    $opTimeoutMs = $installTimeoutMin * 60000

    # Bounded session options: OperationTimeout is sized to the install budget
    # above (a blocking deploy yields no output for its full duration), while
    # OpenTimeout/CancelTimeout stay modest so connect and cancel remain snappy.
    # Lifted from v2.5.4 $script:WSManOpt. $wsManOptSsl is the same budget with
    # SkipCACheck/SkipCNCheck added for a host the per-host probe finds
    # reachable ONLY on WinRM HTTPS 5986 (self-signed cert is common on AFNET).
    $wsManOpt    = New-PSSessionOption -OperationTimeout $opTimeoutMs -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
    $wsManOptSsl = New-PSSessionOption -OperationTimeout $opTimeoutMs -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000 -SkipCACheck -SkipCNCheck

    # Per-host wall-clock watchdog (Wave-3). The WinRM OperationTimeout above
    # bounds ONLY the deploy phase; the SMB mount (New-PSDrive \\host\C$) and the
    # Copy-Item -Recurse over the admin share have NO timeout, so a host that
    # passes the 1.5s TCP-445 probe but then half-opens its share or crawls on a
    # slow link can pin its runspace for minutes on SMB's own timeout, stalling
    # the run on the pool the WSMan option cannot reach. Bound the WHOLE per-host
    # job (probe + repair + mount + copy + deploy) with a GENEROUS wall-clock cap
    # that exceeds the install budget so a long-but-healthy install is never
    # killed: install budget + a 30-min mount/copy/probe/repair grace.
    $maxPerHostMin     = $installTimeoutMin + 30
    $maxPerHostSeconds = $maxPerHostMin * 60

    & $send @{ type='status'; text="Starting '$ActionId' on $($targets.Count) host(s), package '$pkgName', $threads thread(s)..." }
    & $send @{ type='log'; level=''; text="[BULK] mode=$mode targets=$($targets.Count) msis=$($msiList.Count) args='$msiArgs' path='$pkgPath'" }
    if ($mode -eq 'MSI' -and @($msiList).Count -eq 0) {
        & $send @{ type='log'; level='warn'; text='No MSIs checked: the whole bundle folder will be copied and EVERY *.msi found in it installed.' }
    }

    # Seed Queued rows so the operator sees the full target list immediately.
    foreach ($h in $targets) {
        & $send @{ type='row'; Host=$h; Status='Queued'; Detail='Waiting for runspace'; ExitCode=''; Time='' }
    }

    $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $threads, $iss, $Host)

    # Thread-safe step queue: per-host scriptblocks enqueue intermediate phase
    # messages ('Probing','Repairing','Copying','Deploying'); the harvest loop
    # dequeues each pass and streams a live phase row. A host's first action is
    # pushing 'Probing', so any host seen here has actually started executing -
    # $dispatched lets the cancel path tell in-flight hosts from still-Queued.
    $stepQueue  = [System.Collections.Concurrent.ConcurrentQueue[psobject]]::new()
    # Thread-safe map of host -> on-target staged path ("C:\Temp\<pkg>_<stamp>"),
    # populated by each per-host scriptblock the moment it computes its copy
    # target. The driver consults it to sweep staged payloads left behind when
    # the watchdog or an operator-cancel abandons a host (its finally never ran).
    $pathMap    = [System.Collections.Concurrent.ConcurrentDictionary[string,string]]::new()
    # Thread-safe map of host -> $useSsl (WinRM reachable ONLY on 5986), published
    # by each per-host scriptblock alongside $pathMap so the post-loop cleanup
    # sweep (below) can dial an abandoned SSL-only host over HTTPS too.
    $useSslMap  = [System.Collections.Concurrent.ConcurrentDictionary[string,bool]]::new()
    $dispatched = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    # Per-host start stamps (Wave-3 watchdog): a host is stamped the FIRST time it
    # pushes a step (i.e. when it actually starts executing, not when submitted to
    # the pool), so a host still queued behind slow peers is never timed out early.
    $hostStart  = New-Object 'System.Collections.Generic.Dictionary[string,datetime]' ([System.StringComparer]::OrdinalIgnoreCase)

    $jobs = New-Object System.Collections.ArrayList
    $rows      = New-Object System.Collections.ArrayList
    # Hosts abandoned by the watchdog/cancel whose staged payload must be swept
    # after the fan-out loop (their per-host finally never ran to clean it).
    $leaked    = New-Object System.Collections.ArrayList
    $done      = 0
    $okCount   = 0
    $failCount = 0
    $deferred  = 0
    $skipCount = 0
    try {
        # Pool open + the BeginInvoke submit loop are inside this try so a throw
        # in Open()/Create()/BeginInvoke() still reaches the finally that tears
        # the pool down (instead of leaking an open RunspacePool).
        $pool.Open()

        foreach ($comp in $targets) {
            $ps = [powershell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript($script:RpiDeployHostScript)
            [void]$ps.AddArgument($comp)
            [void]$ps.AddArgument($pkgPath)
            [void]$ps.AddArgument($pkgName)
            [void]$ps.AddArgument($Credential)
            [void]$ps.AddArgument($wsManOpt)
            [void]$ps.AddArgument($wsManOptSsl)
            [void]$ps.AddArgument($stepQueue)
            [void]$ps.AddArgument($mode)
            [void]$ps.AddArgument($msiList)
            [void]$ps.AddArgument($msiArgs)
            [void]$ps.AddArgument($pathMap)
            [void]$ps.AddArgument($useSslMap)
            [void]$jobs.Add([pscustomobject]@{ Host=$comp; PS=$ps; Async=$ps.BeginInvoke(); Done=$false })
        }

        while ($done -lt $jobs.Count) {
            # Drain live phase steps first so the grid paints Probing/Copying/etc.
            $msg = $null
            while ($stepQueue.TryDequeue([ref]$msg)) {
                $stepHost = [string]$msg.Hostname
                [void]$dispatched.Add($stepHost)
                if (-not $hostStart.ContainsKey($stepHost)) { $hostStart[$stepHost] = Get-Date }
                & $send @{ type='row'; Host=$msg.Hostname; Status=$msg.Step; Detail=$msg.Detail; ExitCode=''; Time='' }
            }

            foreach ($j in $jobs) {
                if ($j.Done -or -not $j.Async.IsCompleted) { continue }
                $j.Done = $true
                $res = $null
                try { $res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 }
                catch {
                    $res = [pscustomobject]@{ Hostname=$j.Host; Status='Failed'; Reason="Runspace error: $($_.Exception.Message)"; Detail="Runspace error: $($_.Exception.Message)"; ExitCode=$null; RepairAttempted=$false; RepairSucceeded=$false }
                }
                try { $j.PS.Dispose() } catch {}

                $status = if ($res -and $res.Status) { [string]$res.Status } else { 'Failed' }
                # early-return paths (offline / repair-failed) set .Reason but not .Detail
                $detail = if ($res -and $res.Detail) { [string]$res.Detail } elseif ($res -and $res.Reason) { [string]$res.Reason } else { 'Unknown remote error (no structured result)' }
                $exit   = if ($res -and $null -ne $res.ExitCode) { [string]$res.ExitCode } else { '' }
                $repairTag = ''
                $repairTxt = 'not needed'
                if ($res -and $res.PSObject.Properties['RepairAttempted'] -and $res.RepairAttempted) {
                    $repairTag = if ($res.RepairSucceeded) { '[REPAIRED] ' } else { '[REPAIR-FAILED] ' }
                    $repairTxt = if ($res.RepairSucceeded) { 'attempted-succeeded' } else { 'attempted-FAILED' }
                }

                # Popup-only detail (not in the columns list, so only the row
                # modal renders them): full remote output (PSADT stdout or the
                # per-MSI exit table), raw reason, repair outcome and timings.
                $outputTxt = ''
                if ($res -and $res.PSObject.Properties['Output'] -and $res.Output) { $outputTxt = [string]$res.Output }
                $reasonTxt = ''
                if ($res -and $res.PSObject.Properties['Reason'] -and $res.Reason) { $reasonTxt = [string]$res.Reason }
                $started = ''; $ended = ''; $durTxt = ''
                if ($res -and $res.PSObject.Properties['StartTime'] -and $res.StartTime) {
                    $started = ([datetime]$res.StartTime).ToString('yyyy-MM-dd HH:mm:ss')
                }
                if ($res -and $res.PSObject.Properties['EndTime'] -and $res.EndTime) {
                    $ended = ([datetime]$res.EndTime).ToString('yyyy-MM-dd HH:mm:ss')
                }
                if ($started -and $ended) {
                    $durTxt = '{0:hh\:mm\:ss}' -f ([datetime]$res.EndTime - [datetime]$res.StartTime)
                }

                switch ($status) {
                    'Success'            { $okCount++ }
                    'Success (warnings)' { $okCount++ }   # exit code succeeded (soft-fail surfaced via the distinct status + warn log)
                    'Deferred'           { $deferred++ }
                    'AlreadyInstalled'   { $skipCount++ } # loop60: MSI 1638 all-refused - nothing installed, version unverified -> skipped, NOT ok/fail
                    default              { $failCount++ }
                }

                # loop73 (informative failures): on a failure (anything not ok/deferred/skipped),
                # translate the raw remote detail (else reason/output) into an actionable troubleshooting
                # hint (why + how to fix). Carried in a Hint row field + appended to the err log; the raw
                # detail/reason/output are preserved.
                $isFail = ($status -notin @('Success','Success (warnings)','Deferred','AlreadyInstalled'))
                $hint = if ($isFail) { Get-JanetTroubleshootHint -Message $(if ($detail) { $detail } elseif ($reasonTxt) { $reasonTxt } else { $outputTxt }) -Server ([string]$j.Host) } else { '' }

                $row = @{
                    Host=$j.Host; Status=$status; Detail="$repairTag$detail"; ExitCode=$exit; Time=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                    Output=$outputTxt; Reason=$reasonTxt; Repair=$repairTxt; Started=$started; Ended=$ended; Duration=$durTxt; Hint=$hint
                }
                [void]$rows.Add($row)
                & $send (@{ type='row' } + $row)

                # Map to JANET audit buckets: a state-changing install = VulnPatched.
                $auditResult = switch ($status) {
                    'Success'            { 'Success' }
                    'Success (warnings)' { 'Success' }
                    'Deferred'           { 'Skipped' }
                    'AlreadyInstalled'   { 'Skipped' }   # loop60: 1638 all-refused -> Skipped/itemCount 0, never a false VulnPatched
                    default              { 'Failure' }
                }
                $itemCount = if ($auditResult -eq 'Success') { 1 } else { 0 }
                & $send @{ type='audit'; action='VulnPatched'; target=$j.Host; result=$auditResult; itemCount=$itemCount; detail="$pkgName $repairTag$detail" }

                & $send @{ type='log'; level=$(if($status -eq 'Success'){''}elseif($status -eq 'Deferred' -or $status -eq 'Success (warnings)' -or $status -eq 'AlreadyInstalled'){'warn'}else{'err'}); text="${repairTag}[$($j.Host)] $status : $detail$(if ($hint) { ' | FIX: ' + $hint } else { '' })" }

                $done++
                & $send @{ type='progress'; done=$done; total=$jobs.Count }
            }

            # Per-host wall-clock watchdog. A dispatched host whose runspace has
            # run past the generous cap (an unbounded SMB mount/copy the WSMan
            # OperationTimeout cannot reach is the usual culprit) is stopped and
            # recorded as a timeout Failure so one hung host can't pin the run.
            # Only hosts that have actually started (stamped in $hostStart) are
            # eligible; a job that completed since the harvest pass above is left
            # for the next pass to reap normally.
            $wdNow = Get-Date
            foreach ($j in $jobs) {
                if ($j.Done -or $j.Async.IsCompleted) { continue }
                if (-not $hostStart.ContainsKey($j.Host)) { continue }
                $wdElapsed = ($wdNow - $hostStart[$j.Host]).TotalSeconds
                if ($wdElapsed -lt $maxPerHostSeconds) { continue }
                $j.Done = $true
                if ($j.PS) {
                    # BeginStop (non-blocking) then NULL the handle. The pool
                    # Close()/Dispose() in the finally reclaims the runspace after
                    # this timeout row/audit has been emitted (same pattern as the
                    # cancel path - a blocking Stop()/Dispose() here costs ~11s).
                    $wdPs = $j.PS
                    try { [void]$wdPs.BeginStop($null, $null) } catch {}
                    $j.PS = $null
                }
                $wdDetail = "Timed out after $([int]$wdElapsed)s (per-host cap $maxPerHostMin min) - host stopped; SMB mount/copy or deploy did not complete"
                # Record any staged payload this abandoned host left on the target
                # (its finally never ran) so the post-loop sweep can remove it, and
                # surface the path so the operator can clean manually if that fails.
                $wdStaged = ''
                if ($pathMap.ContainsKey($j.Host)) { $wdStaged = [string]$pathMap[$j.Host] }
                if ($wdStaged) {
                    $wdDetail = "$wdDetail; staged payload $wdStaged left on target (cleanup will be attempted)"
                    [void]$leaked.Add([pscustomobject]@{ Host=$j.Host; Path=$wdStaged })
                }
                $failCount++
                $row = @{ Host=$j.Host; Status='Failed'; Detail=$wdDetail; ExitCode=''; Time=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss') }
                [void]$rows.Add($row)
                & $send (@{ type='row' } + $row)
                & $send @{ type='audit'; action='VulnPatched'; target=$j.Host; result='Failure'; itemCount=0; detail="$pkgName timeout: $wdDetail" }
                & $send @{ type='log'; level='err'; text="[$($j.Host)] TIMEOUT : $wdDetail" }
                $done++
                & $send @{ type='progress'; done=$done; total=$jobs.Count }
            }

            if ($done -lt $jobs.Count) {
                # Operator cancel. Hosts never dispatched (still Queued, no step
                # ever pushed) are untouched - audit them Skipped. For in-flight
                # hosts BeginStop stops the local pipeline; in PSADT mode that
                # stop propagates into the remote Invoke-Command pipeline too,
                # while a raw msiexec already launched is a detached process and
                # finishes on the target regardless. Audit each abandoned host so
                # the DoD trail records it, and word the record per case.
                if (& $cancelCheck) {
                    # Drain any last-moment phase steps first so a host that just
                    # started executing is not misclassified as never-dispatched.
                    $msg = $null
                    while ($stepQueue.TryDequeue([ref]$msg)) { [void]$dispatched.Add([string]$msg.Hostname) }
                    $inflightDetail = if ($mode -eq 'MSI') {
                        'cancelled in flight; stop sent, but an msiexec already launched finishes on the target'
                    } else {
                        'cancelled in flight; stop propagated to the remote PSADT pipeline - install may be partial'
                    }
                    $queuedDetail = 'cancelled before dispatch; never dispatched - no changes made'
                    foreach ($j in $jobs) {
                        if ($j.Done) { continue }
                        $j.Done = $true
                        if ($j.PS) {
                            $ps = $j.PS
                            # BeginStop then NULL the handle. Disposing right after
                            # BeginStop blocks ~11s per runspace; the pool
                            # Close()/Dispose() in the finally reclaims them after
                            # every abandon row/audit below has been emitted.
                            try { [void]$ps.BeginStop($null, $null) } catch {}
                            $j.PS = $null
                        }
                        if ($dispatched.Contains($j.Host)) {
                            # Record any staged payload left on this in-flight host so
                            # the post-loop sweep can remove it (its finally never ran),
                            # and surface the path in the row/audit detail.
                            $clStaged = ''
                            if ($pathMap.ContainsKey($j.Host)) { $clStaged = [string]$pathMap[$j.Host] }
                            $detailForRow = $inflightDetail
                            if ($clStaged) {
                                $detailForRow = "$inflightDetail; staged payload $clStaged left on target"
                                [void]$leaked.Add([pscustomobject]@{ Host=$j.Host; Path=$clStaged })
                            }
                            if ($mode -eq 'MSI') {
                                # MSI mode launches a DETACHED msiexec on the target;
                                # the local stop cannot reach it and it finishes on the
                                # host regardless, so its outcome here is genuinely
                                # UNKNOWN. Audit Skipped (not Failure): we have no
                                # evidence the install failed and it may well succeed.
                                $row = @{ Host=$j.Host; Status='Skipped'; Detail=$detailForRow; ExitCode=''; Time=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss') }
                                & $send @{ type='audit'; action='VulnPatched'; target=$j.Host; result='Skipped'; itemCount=0; detail=$detailForRow }
                                $skipCount++
                            } else {
                                # PSADT mode: the stop propagates into the remote
                                # pipeline, actively interrupting the deploy (may be
                                # partial) -- a real, non-successful outcome.
                                $row = @{ Host=$j.Host; Status='Failed'; Detail=$detailForRow; ExitCode=''; Time=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss') }
                                & $send @{ type='audit'; action='VulnPatched'; target=$j.Host; result='Failure'; itemCount=0; detail=$detailForRow }
                                $failCount++
                            }
                        } else {
                            $row = @{ Host=$j.Host; Status='Skipped'; Detail=$queuedDetail; ExitCode=''; Time=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss') }
                            & $send @{ type='audit'; action='VulnPatched'; target=$j.Host; result='Skipped'; itemCount=0; detail='never dispatched - no changes made' }
                            $skipCount++
                        }
                        [void]$rows.Add($row)
                        & $send (@{ type='row' } + $row)
                        $done++
                        & $send @{ type='progress'; done=$done; total=$jobs.Count }
                    }
                    & $send @{ type='log'; level='warn'; text='Cancelled by operator; never-dispatched host(s) skipped (no changes); in-flight host(s) stopped - PSADT pipelines receive the stop, an already-launched msiexec finishes on the target.' }
                    break
                }
                Start-Sleep -Milliseconds 120
            }
        }
        # Final flush of any trailing step messages.
        $msg = $null
        while ($stepQueue.TryDequeue([ref]$msg)) { }
    } finally {
        try { $pool.Close(); $pool.Dispose() } catch {}
    }

    # Best-effort staged-payload cleanup sweep. Hosts abandoned by the watchdog
    # or operator-cancel never ran their per-host finally, so the staged
    # C:\Temp\<pkg>_<stamp> copy leaks on the target. Remove it via a bounded,
    # short-timeout credentialed WinRM session (bounded so a still-unreachable
    # host cannot re-hang the run); any failure only logs - the leaked path is
    # already in the row detail so the operator can clean it manually.
    if ($leaked.Count -gt 0) {
        & $send @{ type='log'; level=''; text="[CLEANUP] sweeping staged payload(s) on $($leaked.Count) abandoned host(s)..." }
        $sweepOpt    = New-PSSessionOption -OpenTimeout 10000 -OperationTimeout 30000 -CancelTimeout 5000
        # SSL variant for a host the per-host probe found reachable ONLY on 5986
        # ($useSslMap, published alongside $pathMap) -- otherwise this sweep would
        # dial HTTP 5985 on a host that never had it open.
        $sweepOptSsl = New-PSSessionOption -OpenTimeout 10000 -OperationTimeout 30000 -CancelTimeout 5000 -SkipCACheck -SkipCNCheck
        foreach ($lk in $leaked) {
            $lkHost = [string]$lk.Host
            $lkPath = [string]$lk.Path
            if ([string]::IsNullOrWhiteSpace($lkPath)) { continue }
            $lkUseSsl = $false
            if ($useSslMap.ContainsKey($lkHost)) { $lkUseSsl = [bool]$useSslMap[$lkHost] }
            $sweepSess = $null
            try {
                $sweepSplat = @{ ComputerName=$lkHost; Authentication='Negotiate'; SessionOption=$(if ($lkUseSsl) { $sweepOptSsl } else { $sweepOpt }); ErrorAction='Stop' }
                if ($Credential) { $sweepSplat['Credential'] = $Credential }
                if ($lkUseSsl) { $sweepSplat['UseSSL'] = $true }
                $sweepSess = New-PSSession @sweepSplat
                Invoke-Command -Session $sweepSess -ArgumentList $lkPath -ScriptBlock {
                    param($p)
                    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Recurse -Force -EA SilentlyContinue }
                } -EA Stop
                & $send @{ type='log'; level=''; text="[CLEANUP] $lkHost : removed staged payload $lkPath" }
            } catch {
                & $send @{ type='log'; level='warn'; text="[CLEANUP] $lkHost : could not remove staged payload $lkPath ($($_.Exception.Message)); clean it manually" }
            } finally {
                if ($sweepSess) { Remove-PSSession -Session $sweepSess -EA SilentlyContinue }
            }
        }
    }

    & $send @{ type='status'; text="Done. $okCount ok, $deferred deferred, $failCount failed, $skipCount skipped of $($jobs.Count)." }
    & $send @{ type='log'; level=''; text="[BULK] complete success=$okCount deferred=$deferred failed=$failCount skipped=$skipCount of $($jobs.Count)" }
    return @{ rows = @($rows); summary = @{ total=$jobs.Count; ok=$okCount; failed=$failCount; deferred=$deferred; skipped=$skipCount } }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction
