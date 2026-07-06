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
#  Contract:
#    Get-JanetToolManifest                          -> tool + action descriptors
#    Invoke-JanetToolAction -ActionId -Params -Credential -Emit  -> { rows; summary }
#  -Emit event shapes consumed by the UI: status / progress / row / log / audit.
# =============================================================================

function Get-JanetToolManifest {
    @{
        id       = 'pkginstall'
        name     = 'Remote Package Installer'
        version  = '2.5.6'
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
                    @{ name='packagePath'; label='Package'; type='select'; optionsFrom='pkginstall-packages'; optionsArg='psadt'; required=$false; help='Pick a package (each is a folder with a Deploy-Application.ps1 dropped in the Packages folder shown below). Click the refresh button after adding new ones.' },
                    @{ name='packagePathManual'; label='...or a custom package path (UNC/local)'; type='text'; required=$false },
                    @{ name='packageName'; label='Package name (audit/display; blank = folder name)'; type='text'; required=$false },
                    @{ name='threads';     label='Parallel hosts';                          type='int';      required=$false; default=8 },
                    @{ name='installTimeoutMin'; label='Per-host install timeout (min)';     type='int';      required=$false; default=30 }
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
                    @{ name='installTimeoutMin'; label='Per-host install timeout (min)'; type='int';      required=$false; default=30 }
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

function ConvertTo-JanetMsiList {
    # Split a pasted blob into relative MSI paths (one per line). Preserves
    # subdir entries like 'x64\foo.msi'. Returns @() when blank (caller then
    # falls back to discovering *.msi recursively under the bundle folder).
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return @() }
    # Reject a rooted path (C:\, \, \\server) or any '..' segment: each entry MUST
    # stay inside the bundle. Otherwise a pasted '..\..\Windows\System32\x.msi' would
    # read outside $PkgPath and write outside the target's staging dir. Subdir
    # entries like 'x64\foo.msi' are kept.
    @($Raw -split '[\r\n]+' | ForEach-Object { $_.Trim() } | Where-Object {
        $_ -and -not [System.IO.Path]::IsPathRooted($_) -and ($_ -notmatch '(^|[\\/])\.\.([\\/]|$)')
    })
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
        $StepQueue,
        [string]$Mode = 'PSADT',
        [string[]]$MsiList = @(),
        [string]$MsiArgs = '/qn /norestart',
        $PathMap
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

    try {
        ## 1. Probe 5985 (the port we actually need for WinRM). Inlined because
        ## the runspace can't see Test-RpiReachable from outer scope.
        & $pushStep 'Probing' 'TCP probe 5985'
        $winrmOpen = $false
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
            ## 1a. WinRM closed. Probe SMB (445) -- if THAT's open we have a
            ## DCOM-repair side-channel.
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
                $r.Reason = 'Machine is offline or unreachable (no TCP on 5985 or 445)'
                return $r
            }

            ## 1b. SMB open + WinRM closed -> attempt DCOM bootstrap of WinRM.
            ## Two-attempt CIM connect, then ChangeStartMode + StartService +
            ## winrm quickconfig (with -skipNetworkProfileCheck), then re-probe
            ## 5985 with a 30s budget. Requires a credential for the DCOM session.
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
        if ($PathMap) { $PathMap[$Computer] = $remoteLocalPath }

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
            & $pushStep 'Deploying' 'Running Deploy-Application.ps1'
        }
        if ($Credential) {
            $session = New-PSSession -ComputerName $Computer -Credential $Credential -Authentication Negotiate -SessionOption $WSManOpt -EA Stop
        } else {
            $session = New-PSSession -ComputerName $Computer -Authentication Negotiate -SessionOption $WSManOpt -EA Stop
        }

        if ($Mode -eq 'MSI') {
            ## MSI bundle mode. For each selected MSI (filename relative to the
            ## copied bundle root), shell `msiexec /i <full> $MsiArgs /L*v <log>`
            ## on the remote and capture per-MSI exit codes. Host aggregate Status
            ## is Success only when EVERY MSI returned a success exit (0/1641/3010).
            $invokeResult = Invoke-Command -Session $session -ArgumentList $remoteLocalPath, $MsiList, $MsiArgs -ScriptBlock {
                param($destPath, $msiList, $msiArgs)
                $res = [pscustomobject]@{
                    Status   = 'Failed'
                    ExitCode = $null
                    Reason   = ''
                    Output   = ''
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
                            1638    { $status = 'AlreadyCompliant'; $reason = 'Another version already installed (1638) - treated as already compliant, not a failure' }
                            default {
                                if ($null -eq $exit) { $status = 'Failed'; $reason = 'msiexec failed to launch (no exit code)' }
                                else                 { $status = 'Failed'; $reason = "msiexec exit $exit - see $logFile" }
                            }
                        }
                        $perMsi.Add([pscustomobject]@{ Msi=$rel; ExitCode=$exit; Status=$status; Reason=$reason })
                        # Only a genuine 'Failed' seeds the first-failure marker. 'AlreadyCompliant'
                        # (MSI 1638) is a distinct non-failure state and must not trip the fail path.
                        if ($status -eq 'Failed' -and -not $firstFailMsi) {
                            $firstFailMsi  = $rel
                            $firstFailExit = $exit
                        }
                        [void]$sb.AppendLine("[$rel] exit=$exit  $reason")
                    }

                    $totalCount     = $perMsi.Count
                    $successCount   = @($perMsi | Where-Object { $_.Status -eq 'Success' }).Count
                    $compliantCount = @($perMsi | Where-Object { $_.Status -eq 'AlreadyCompliant' }).Count
                    # Only genuine failures count against the run. AlreadyCompliant (MSI 1638 -
                    # another version already installed) is neither success nor failure.
                    $failCount      = @($perMsi | Where-Object { $_.Status -eq 'Failed' }).Count

                    if ($totalCount -eq 0) {
                        $res.Status = 'Failed'
                        $res.Reason = 'No MSIs to install (empty selection)'
                    } elseif ($failCount -eq 0) {
                        $res.Status = 'Success'
                        if ($successCount -eq 0 -and $compliantCount -eq $totalCount) {
                            $res.Reason = "All $totalCount MSI(s) already compliant (another version already installed; nothing to do)"; $res.ExitCode = 1638
                        }
                        elseif ($sawRebootInit)   { $res.Reason = "All $totalCount MSI(s) succeeded (reboot initiated)"; $res.ExitCode = 1641 }
                        elseif ($sawReboot)   { $res.Reason = "All $totalCount MSI(s) succeeded (reboot required)";  $res.ExitCode = 3010 }
                        else {
                            $compliantNote = if ($compliantCount -gt 0) { " ($compliantCount already compliant)" } else { '' }
                            $res.Reason = "All $totalCount MSI(s) succeeded$compliantNote"; $res.ExitCode = 0
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
            $invokeResult = Invoke-Command -Session $session -ArgumentList $remoteLocalPath -ScriptBlock {
                param($destPath)
                $res = [pscustomobject]@{
                    Status   = 'Failed'
                    ExitCode = $null
                    Reason   = ''
                    Output   = ''
                }
                try {
                    Get-ChildItem -Path $destPath -Filter *.ps1 -Recurse -EA SilentlyContinue | Unblock-File
                    $deploy = Get-ChildItem -Path $destPath -Filter 'Deploy-Application.ps1' -Recurse -File -EA SilentlyContinue | Select-Object -First 1
                    if (-not $deploy) {
                        $res.Reason = 'Deploy-Application.ps1 not found in package'
                        return $res
                    }
                    Set-Location $deploy.DirectoryName
                    $global:LASTEXITCODE = 0
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
                    if ($successExits -contains $exitCode) {
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
        if ($singleMsiLeaf) { $msiList = @($singleMsiLeaf) }
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
    # Lifted from v2.5.4 $script:WSManOpt.
    $wsManOpt = New-PSSessionOption -OperationTimeout $opTimeoutMs -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000

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
            [void]$ps.AddArgument($stepQueue)
            [void]$ps.AddArgument($mode)
            [void]$ps.AddArgument($msiList)
            [void]$ps.AddArgument($msiArgs)
            [void]$ps.AddArgument($pathMap)
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
                    default              { $failCount++ }
                }

                $row = @{
                    Host=$j.Host; Status=$status; Detail="$repairTag$detail"; ExitCode=$exit; Time=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                    Output=$outputTxt; Reason=$reasonTxt; Repair=$repairTxt; Started=$started; Ended=$ended; Duration=$durTxt
                }
                [void]$rows.Add($row)
                & $send (@{ type='row' } + $row)

                # Map to JANET audit buckets: a state-changing install = VulnPatched.
                $auditResult = switch ($status) {
                    'Success'            { 'Success' }
                    'Success (warnings)' { 'Success' }
                    'Deferred'           { 'Skipped' }
                    default              { 'Failure' }
                }
                $itemCount = if ($auditResult -eq 'Success') { 1 } else { 0 }
                & $send @{ type='audit'; action='VulnPatched'; target=$j.Host; result=$auditResult; itemCount=$itemCount; detail="$pkgName $repairTag$detail" }

                & $send @{ type='log'; level=$(if($status -eq 'Success'){''}elseif($status -eq 'Deferred' -or $status -eq 'Success (warnings)'){'warn'}else{'err'}); text="${repairTag}[$($j.Host)] $status : $detail" }

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
        $sweepOpt = New-PSSessionOption -OpenTimeout 10000 -OperationTimeout 30000 -CancelTimeout 5000
        foreach ($lk in $leaked) {
            $lkHost = [string]$lk.Host
            $lkPath = [string]$lk.Path
            if ([string]::IsNullOrWhiteSpace($lkPath)) { continue }
            $sweepSess = $null
            try {
                if ($Credential) {
                    $sweepSess = New-PSSession -ComputerName $lkHost -Credential $Credential -Authentication Negotiate -SessionOption $sweepOpt -EA Stop
                } else {
                    $sweepSess = New-PSSession -ComputerName $lkHost -Authentication Negotiate -SessionOption $sweepOpt -EA Stop
                }
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
