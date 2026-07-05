# =============================================================================
#  JanetWeb.winupgrade.psm1  -  Windows Upgrade tool engine for JANET Web
#  (Re-forked for JANET Web from the proven JANET ONE engine; cross-checked vs the desktop tool + ui-spec.)
#
#  Ported from dev\WindowsUpgradeTool_0.1.0.ps1 (engine reused, WinForms layer
#  dropped). Drives Windows feature-update work across many hosts over WinRM,
#  fanned out in parallel with a per-host .NET ping pre-check and live streaming:
#
#    diagnose   - read-only 24H2 readiness + WU health scan (ported verbatim from
#                 the desktop $sbDiagnostic); one verdict row per host + the full
#                 colour-tagged report streamed to the activity log.
#    pin        - write the Windows Update for Business "Target Release Version"
#                 policy so a PC holds at a feature build (e.g. Windows 11 24H2)
#                 and is NOT offered a newer feature release until unpinned.
#                 v0.3.0 adds optional SCCM/MECM client refresh + CPU/TPM bypass.
#    unpin      - remove that policy so the PC tracks its normal update ring.
#                 v0.3.0 optionally also removes the CPU/TPM bypass key (default on).
#    forcediscovery - safe or aggressive WU reset + re-scan (ported verbatim from
#                 the desktop $sbForceDiscovery) for when 24H2 will not surface.
#    installcab - copy a feature-update .cab/.msu to C:\Temp on each target and
#                 install it with DISM /Online /Add-Package, optional reboot.
#    ping       - reachability sweep (latency or Unreachable).
#
#  v0.3.0: diagnose + forcediscovery ported verbatim from References\24h2script.ps1
#  (the desktop "24H2 Remote Helper"); pin/unpin gained the bypass + SCCM options.
#
#  Contract:
#    Get-JanetToolManifest                          -> tool + action descriptors
#    Invoke-JanetToolAction -ActionId -Params -Credential -Emit  -> { rows; summary }
#  -Emit event shapes consumed by the UI: status / progress / row / log / audit.
#
#  Notes for the web (stateless) model vs the desktop tool:
#    - Per-host intermediate phases ("Copying...", "Installing...") are not
#      streamed; one final row per host is emitted on completion (suite parity
#      with the other modules' harvest loops). The progress bar tracks done/total.
#    - The CAB/MSU is taken as a path on THIS admin box (where the server runs),
#      mirroring the desktop Browse result; the worker copies it to each target.
#    - DISM can run for minutes, so installcab uses a long per-host watchdog.
# =============================================================================

function Get-JanetToolManifest {
    @{
        id       = 'winupgrade'
        name     = 'Windows Upgrade'
        version  = '0.3.0'
        category = 'Remediation'
        summary  = 'Pin/unpin the Windows feature-update target version and push feature-update CAB/MSU packages (DISM) across many workstations in parallel. Two common jobs: the 24H2 UPGRADE (Pin to Windows 11 24H2, then let Windows Update / MECM install it) and the 25H2 UPDATE (Install the 25H2 enablement-package CAB; Unpin first if the fleet is pinned). Also diagnoses a failed in-place upgrade: Check Upgrade Errors reads setuperr.log and flags the out-of-memory build failure (0x8007000E), and Set Page File applies the fix (fixed 16 GB page file).'
        actions  = @(
            @{
                id          = 'diagnose'
                label       = 'Run Diagnostic Scan'
                description  = 'Read-only 24H2 readiness + Windows Update health scan (changes NOTHING). Per host it checks CPU / TPM / Secure Boot / RAM / disk against the Windows 11 24H2 minimums, the Target Release Version policy + CPU/TPM bypass state, feature-update deferrals / pauses (blocks), the WU service health, and SCCM client 24H2 deployment visibility, then returns a one-word verdict: ON 24H2 (already build 26100+); HW INCOMPAT (unsupported CPU/TPM and no bypass set); BLOCKED (a deferral / pause is holding the feature update); NEEDS POLICY (Target Release Version not set); READY (all clear to Pin / Force Discovery). The full colour-coded report streams to the activity log.'
                kind         = 'stream-table'
                destructive  = $false
                columns      = @('Host','Ping','Status','Detail')
                inputs       = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=16 }
                )
            },
            @{
                id          = 'pin'
                label       = 'Pin Feature Version'
                description  = '24H2 UPGRADE job: hold targets at a feature version (Windows Update for Business Target Release Version policy) - e.g. Product "Windows 11", Version "24H2". WU keeps offering monthly quality fixes but will NOT move the PC to a newer feature build until you Unpin. Pin sets a CEILING; it does not push the install - each PC moves on its next Windows Update / MECM check (a reboot + Check for updates applies it promptly).'
                kind         = 'stream-table'
                destructive  = $true
                columns      = @('Host','Ping','Status','Detail')
                inputs       = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='product'; label='Product';  type='text'; required=$true; default='Windows 11'; help='Windows Update for Business ProductVersion value, e.g. "Windows 11". This is the gpedit "Select the Target Feature Update" Product field.' },
                    @{ name='version'; label='Version';  type='text'; required=$true; default='24H2'; help='TargetReleaseVersionInfo value, e.g. "24H2" - the build to hold at. This is the gpedit "Select the Target Feature Update" Target Version field.' },
                    @{ name='runWu'; label='Also trigger a Windows Update scan after pinning'; type='bool'; required=$false; default=$false; help='After writing the policy, kick the Windows Update agent (the built-in Scheduled Start task) so the pinned build is detected and offered sooner - the "then run Windows Update" step of the manual gpedit procedure.' },
                    @{ name='sccmRefresh'; label='Also refresh the SCCM / MECM client (pull policy so Software Center updates)'; type='bool'; required=$false; default=$false; help='After the policy write (and after the optional WU scan) trigger the SCCM client schedule cycles (Machine Policy / Software Updates Deployment Evaluation, etc.) so an assigned Software Center 24H2 deployment surfaces without waiting for the next machine-policy cycle.' },
                    @{ name='bypass'; label='Apply CPU/TPM bypass for unsupported hardware (MoSetup)'; type='bool'; required=$false; default=$false; help='WARNING: sets HKLM:\SYSTEM\Setup\MoSetup\AllowUpgradesWithUnsupportedTPMOrCPU = 1 so a PC with an unsupported CPU / TPM can take the 24H2 feature update. This is a Microsoft-unsupported configuration; such devices may not receive all future updates.' },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='dryRun'; label='Dry-run (no changes)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=16 }
                )
            },
            @{
                id          = 'unpin'
                label       = 'Unpin (remove hold)'
                description  = 'Remove the Target Release Version policy so the PC follows its normal Windows Update path again and can move to newer feature builds. Use this to reverse a Pin - e.g. run Unpin FIRST before pushing the 25H2 update to a fleet that was pinned to 24H2 (keeps the WU policy consistent; DISM installs regardless of the pin).'
                kind         = 'stream-table'
                destructive  = $true
                columns      = @('Host','Ping','Status','Detail')
                inputs       = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='removeBypass'; label='Also remove the CPU/TPM bypass key (MoSetup)'; type='bool'; required=$false; default=$true; help='Also delete HKLM:\SYSTEM\Setup\MoSetup\AllowUpgradesWithUnsupportedTPMOrCPU (the CPU/TPM upgrade bypass) when unpinning, returning the device to a supported-hardware-only stance. On by default so an Unpin fully reverses a bypassed Pin.' },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='dryRun'; label='Dry-run (no changes)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=16 }
                )
            },
            @{
                id          = 'forcediscovery'
                label       = 'Force Update Discovery'
                description  = 'Force targets to re-check for the pinned feature update when 24H2 still does not appear after Pin. Safe mode (default) re-applies the Target Release Version policy, reports (does NOT remove) any deferrals / pauses, triggers the SCCM client cycles, runs gpupdate /force /target:computer, and kicks a Windows Update scan (DetectNow + UsoClient StartScan). Aggressive mode ALSO removes the deferral / pause policy values, STOPS the WU services, renames SoftwareDistribution + catroot2, re-registers the Windows Update DLLs, restarts the services, re-applies the policy and re-scans - a full WU cache reset. Use aggressive only if safe mode does not resolve. Emits one verdict row per host and streams the full step-by-step log to the activity log.'
                kind         = 'stream-table'
                destructive  = $true
                confirm      = 'Force update discovery on these targets. Safe mode re-applies the target-release policy and triggers SCCM / GPO / Windows Update scans. If "Aggressive mode" is ticked and this is NOT a Dry-run, each target will STOP the Windows Update services, RENAME SoftwareDistribution + catroot2, and RE-REGISTER the Windows Update DLLs (a full WU cache reset). Proceed?'
                columns      = @('Host','Ping','Status','Detail')
                inputs       = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='product'; label='Product'; type='text'; required=$true; default='Windows 11'; help='Windows Update for Business ProductVersion re-applied before the scan, e.g. "Windows 11".' },
                    @{ name='version'; label='Version'; type='text'; required=$true; default='24H2'; help='TargetReleaseVersionInfo re-applied before the scan, e.g. "24H2".' },
                    @{ name='aggressive'; label='Aggressive mode (clear WU caches, remove deferrals, re-register DLLs)'; type='bool'; required=$false; default=$false; help='WARNING: stops the WU services, renames SoftwareDistribution + catroot2, re-registers the Windows Update DLLs and removes deferral / pause policy values - a full WU reset. Use only if safe mode does not surface the update.' },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='dryRun'; label='Dry-run (no changes)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=8 }
                )
            },
            @{
                id          = 'installcab'
                label       = 'Install Feature CAB'
                description  = '25H2 UPDATE job: copy a feature-update .cab/.msu (e.g. the 25H2 enablement package KB5054156) to C:\Temp on each target and install it with DISM /Online /Add-Package, optionally rebooting ~10s after a successful install. A CAB install changes the build directly and IGNORES a Pin - if the fleet is pinned to 24H2, run Unpin FIRST to keep the WU policy consistent.'
                kind         = 'stream-table'
                destructive  = $true
                confirm      = 'Install the selected CAB/MSU on these targets with DISM /Add-Package. If "Reboot target ~10s after a successful install" is ticked and this is NOT a Dry-run, each target will REBOOT about 10 seconds after a successful install. Proceed?'
                columns      = @('Host','Ping','Status','Detail')
                inputs       = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='cabPath'; label='CAB/MSU path (on this admin box / a share)'; type='text'; required=$false; help='Full local or UNC path to the .cab/.msu readable by the machine running JANET Web. OR use Browse below to pick/upload one. Copied to C:\Temp on each target, then installed with DISM. A UNC \\server\share path must be readable by the target machine accounts (the in-session pull is a second hop); otherwise it falls back to copying via the admin uplink.' },
                    @{ name='cabUpload'; label='...or Browse / drag a .cab/.msu to upload'; type='file'; required=$false; filter='Update packages (*.cab;*.msu)|*.cab;*.msu|All files (*.*)|*.*'; help='Pick a package in your browser; it uploads to a server temp path that the engine then copies to each target. For very large packages, prefer the path field above pointed at a share (1 GB upload cap).' },
                    @{ name='reboot'; label='Reboot target ~10s after a successful install'; type='bool'; required=$false; default=$true },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='dryRun'; label='Dry-run (no changes)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=8 }
                )
            },
            @{
                id          = 'checkupgrade'
                label       = 'Check Upgrade Errors'
                description  = 'Read-only diagnosis of a failed in-place feature upgrade: reads C:\$WINDOWS.~BT\Sources\Panther\setuperr.log on each target and flags the out-of-memory build failure (E_OUTOFMEMORY 0x8007000E) that the page-file fix resolves. Statuses: MEMORY = out-of-memory, run Set Page File; ERRORS = setup errors logged (other cause); CLEAN = log present, no errors; NO LOG = no recent in-place upgrade attempt. Changes nothing.'
                kind         = 'stream-table'
                destructive  = $false
                columns      = @('Host','Ping','Status','Detail')
                inputs       = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=16 }
                )
            },
            @{
                id          = 'setpagefile'
                label       = 'Set Page File (fix memory exhaustion)'
                description  = 'Upgrade memory-exhaustion fix: disable Windows automatic page-file management and set the C: page file to a FIXED size (default 16384 MB / 16 GB), then reboot to apply (a reboot is required for the new size to take effect). Use this on the hosts that Check Upgrade Errors flagged MEMORY (0x8007000E), then re-run the feature update.'
                kind         = 'stream-table'
                destructive  = $true
                confirm      = 'Disable automatic page-file management and set the C: page file to a fixed size on these targets. If "Reboot target ~10s after setting" is ticked and this is NOT a Dry-run, each target will REBOOT about 10 seconds after the change - a reboot is REQUIRED for the new page-file size to take effect. Proceed?'
                columns      = @('Host','Ping','Status','Detail')
                inputs       = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='sizeMb'; label='Page file size (MB)'; type='int'; required=$false; default=16384; help='Fixed initial = maximum page-file size in MB on C:. 16384 = 16 GB. Clamped to 1024-131072.' },
                    @{ name='reboot'; label='Reboot target ~10s after setting (required to apply)'; type='bool'; required=$false; default=$true },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='dryRun'; label='Dry-run (no changes)'; type='bool'; required=$false; default=$false },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=8 }
                )
            },
            @{
                id          = 'ping'
                label       = 'Ping Sweep'
                description  = 'Quick reachability check across the target list (changes nothing).'
                kind         = 'stream-table'
                destructive  = $false
                columns      = @('Host','Ping','Status')
                inputs       = @(
                    @{ name='targets'; label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=32 }
                )
            }
        )
    }
}

function ConvertTo-JanetHostList {
    # Split a pasted blob into clean, unique, upper-cased host tokens. '#' starts a
    # comment to end-of-line (full '# header' line OR trailing 'host # note'), so a
    # pasted commented list does not leak its words in as bogus hosts. Validity is
    # checked separately by Test-JanetTargetToken in the caller.
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return @() }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $out  = New-Object System.Collections.ArrayList
    foreach ($line in ($Raw -split '\r?\n')) {
        $l = $line
        $hash = $l.IndexOf('#')
        if ($hash -ge 0) { $l = $l.Substring(0, $hash) }
        foreach ($tok in ($l -split '[\s,;]+')) {
            $h = $tok.Trim()
            if ($h -and $seen.Add($h)) { [void]$out.Add($h.ToUpperInvariant()) }
        }
    }
    return $out.ToArray()
}

function Test-JanetTargetToken {
    # A target must be either a strict DNS-ish hostname OR a literal IP address -
    # stops a pasted UNC fragment, account-qualified name, URL, etc. from flowing
    # into New-PSSession / Invoke-Command and mis-targeting. (Shared with pkginstall.)
    param([string]$Token)
    if ([string]::IsNullOrWhiteSpace($Token)) { return $false }
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($Token, [ref]$ip)) { return $true }
    return ($Token -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$')
}

function ConvertTo-JanetBool {
    param($Value, [bool]$Default = $false)
    if ($null -eq $Value) { return $Default }
    if ($Value -is [bool]) { return [bool]$Value }
    if ("$Value" -eq '') { return $Default }
    return ("$Value" -match '^(?i:true|1|yes|on)$')
}

# --- SCCM CLIENT CYCLES (copied EXACTLY from References\24h2script.ps1 lines 27-33) ---
# Machine Policy Retrieval & Eval, Software Updates Deployment Eval / Scan, etc.
$script:WinUpgradeCycles = @(
    "{00000000-0000-0000-0000-000000000021}",
    "{00000000-0000-0000-0000-000000000022}",
    "{00000000-0000-0000-0000-000000000113}",
    "{00000000-0000-0000-0000-000000000108}",
    "{00000000-0000-0000-0000-000000000121}"
)

# --- WINDOWS 11 24H2 MINIMUM REQUIREMENTS (reference lines 36-52) ---
$script:WinUpgradeMinRAMGB      = 4
$script:WinUpgradeMinDiskGB     = 64
$script:WinUpgradeMinTPMVersion = "2.0"
$script:WinUpgradeCpuPatterns = @(
    'i[3579]-[89]\d{3}',
    'i[3579]-10\d{3}',
    'i[3579]-1[1-4]\d{3}',
    'Core\s*Ultra',
    'Xeon\s*W-1[2-3]\d{2}',
    'Ryzen\s*[3579]\s*[3-9]\d{3}',
    'Ryzen\s*[3579]\s*PRO\s*[3-9]\d{3}',
    'EPYC\s*7[2-9]\d{2}',
    'SQ[123]',
    'Snapdragon\s*[78]cx',
    'Snapdragon\s*X\s*(Elite|Plus)'
)

# Per-host worker. Runs in an isolated runspace -- NO outer-scope vars are
# visible; everything comes via .AddArgument(). Returns one [ordered] result
# (Host/Ping/Status/Detail/Ok); the harvest loop turns it into a streamed row.
# Native exit codes (DISM, shutdown) are captured via ProcessStartInfo, NOT the
# call operator, because PS 5.1 wraps a native command's stderr in ErrorRecord
# objects which Invoke-Command then reports as remote errors and corrupts the
# exit code. ProcessStartInfo bypasses that.
$script:WinUpgradeWorker = {
    param(
        [string]$Computer,
        [string]$Op,            # Pin | Unpin | InstallCab | CheckUpgrade | SetPageFile | Ping | Diagnose | ForceDiscovery
        $Cred,                  # PSCredential or $null
        [string]$Product,
        [string]$Version,
        [string]$CabPath,
        [string]$CabName,
        [bool]$CabFromShare,    # $true when CabPath is an operator-typed UNC share (target pulls it)
        [bool]$Reboot,
        [bool]$AttemptOffline,
        [bool]$DryRun,
        [bool]$RunWu,           # Pin: also kick a Windows Update scan after writing the policy
        [int]$SizeMb,           # SetPageFile: fixed C: page-file size in MB
        $CancelJob,             # synchronized hashtable with a 'Cancel' flag, or $null
        $StepQueue,             # ConcurrentQueue for live phase steps (Copying/DISM/Rebooting), or $null
        # --- v0.3.0 appended params (kept at the END so existing positional args are unshifted) ---
        [bool]$Aggressive,      # ForceDiscovery: aggressive WU reset (stop svcs, rename caches, re-reg DLLs)
        [bool]$Bypass,          # Pin: also set the MoSetup CPU/TPM upgrade bypass value = 1
        [bool]$SccmRefresh,     # Pin: also trigger the SCCM client schedule cycles
        [bool]$RemoveBypass,    # Unpin: also remove the MoSetup CPU/TPM bypass value
        $CpuPatterns,           # Diagnose: supported-CPU regex array (reference lines 40-52)
        [int]$MinRAM,           # Diagnose: minimum RAM GB (4)
        [int]$MinDisk,          # Diagnose: minimum free disk GB (64)
        [string]$MinTPM,        # Diagnose: minimum TPM version ("2.0")
        $Cycles                 # ForceDiscovery/Pin SCCM refresh: SCCM client schedule GUID array
    )

    $r = [ordered]@{ Host = $Computer; Ping = ''; Status = ''; Detail = ''; Ok = $false; Report = '' }
    $isCancelled = { if ($CancelJob) { try { [bool]$CancelJob['Cancel'] } catch { $false } } else { $false } }
    # enqueue a live phase step the harvest loop streams as a row (parity with pkginstall).
    $pushStep = { param($step, $detail) if ($StepQueue) { try { [void]$StepQueue.Enqueue([pscustomobject]@{ Hostname=$Computer; Step=$step; Detail=$detail }) } catch {} } }

    if (& $isCancelled) { $r.Status = 'Cancelled'; $r.Detail = 'cancelled before start'; return $r }

    # ---- reachability pre-check: pure-TCP probe (AFNET-safe; never ICMP). Loop
    # WinRM 5985 then SMB 445, TcpClient.BeginConnect with a 1500ms connect timeout,
    # break on first connect. (mirrors the wpt ping-sweep TcpClient.BeginConnect probe.)
    $online = $false
    foreach ($port in 5985, 445) {
        $tc = $null
        try {
            $tc  = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) { $online = $true; $r.Ping = "TCP $port" }
        } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
        if ($online) { break }
    }
    if (-not $online) { $r.Ping = 'Unreachable' }

    if ($Op -eq 'Ping') {
        if ($online) { $r.Status = 'Online';  $r.Detail = "Reachable ($($r.Ping))"; $r.Ok = $true }
        else         { $r.Status = 'Offline'; $r.Detail = 'No TCP on 5985/445 (1.5s timeouts)' }
        return $r
    }

    if (-not $online -and -not $AttemptOffline) {
        $r.Status = 'Skipped'; $r.Detail = 'Offline (TCP 5985/445 unreachable). Enable "Attempt even if offline" to force.'
        return $r
    }

    $credSet  = ($null -ne $Cred)
    $authNote = if ($credSet) { "as $($Cred.UserName)" } else { 'current session' }

    try {
        switch ($Op) {

            'Pin' {
                if ($DryRun) {
                    $wouldParts = @("pin to $Product $Version")
                    if ($Bypass)      { $wouldParts += 'apply the CPU/TPM bypass (MoSetup)' }
                    if ($RunWu)       { $wouldParts += 'trigger a Windows Update scan' }
                    if ($SccmRefresh) { $wouldParts += 'refresh the SCCM client' }
                    $r.Status = 'DRY-RUN'; $r.Detail = "Would $([string]::Join(', ', $wouldParts)) ($authNote)."; $r.Ok = $true; break
                }
                $pinNote = if ($Bypass) { "Writing TargetReleaseVersion policy ($Product $Version) + CPU/TPM bypass..." } else { "Writing TargetReleaseVersion policy ($Product $Version)..." }
                & $pushStep 'Pinning' $pinNote
                # $doBypass appended at the END of the remote param() (matches the call-site
                # ArgumentList order). MoSetup key + value name copied EXACTLY from the
                # reference $sbApply (lines 653-657).
                $sb = {
                    param($tv, $prod, $doBypass)
                    $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
                    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
                    New-ItemProperty -Path $regPath -Name 'TargetReleaseVersion'     -PropertyType DWord  -Value 1    -Force | Out-Null
                    New-ItemProperty -Path $regPath -Name 'ProductVersion'           -PropertyType String -Value $prod -Force | Out-Null
                    New-ItemProperty -Path $regPath -Name 'TargetReleaseVersionInfo' -PropertyType String -Value $tv   -Force | Out-Null
                    $msg = "ProductVersion=$prod; TargetReleaseVersionInfo=$tv"
                    if ($doBypass) {
                        $moKey = 'HKLM:\SYSTEM\Setup\MoSetup'
                        if (-not (Test-Path $moKey)) { New-Item -Path $moKey -Force | Out-Null }
                        New-ItemProperty -Path $moKey -Name 'AllowUpgradesWithUnsupportedTPMOrCPU' -Value 1 -PropertyType DWord -Force | Out-Null
                        $msg += '; CPU/TPM BYPASS SET (MoSetup\AllowUpgradesWithUnsupportedTPMOrCPU=1)'
                    }
                    $msg
                }
                $so = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 60000 -CancelTimeout 5000
                $ic = @{ ComputerName=$Computer; ScriptBlock=$sb; ArgumentList=@($Version,$Product,$Bypass); Authentication='Negotiate'; SessionOption=$so; ErrorAction='Stop' }
                if ($credSet) { $ic.Credential = $Cred }
                $out = Invoke-Command @ic
                $detailParts = @("Pinned: $out")
                # "Then run Windows Update": optionally kick the WU agent so the pinned build
                # is detected/offered without waiting for the next scheduled scan. Best-effort -
                # a trigger failure never fails the pin (the policy is already written).
                if ($RunWu) {
                    & $pushStep 'Scanning' 'Pinned; triggering a Windows Update scan...'
                    $wuSb = {
                        try { Start-ScheduledTask -TaskPath '\Microsoft\Windows\WindowsUpdate\' -TaskName 'Scheduled Start' -ErrorAction Stop; 'WU scan triggered (Scheduled Start task)' }
                        catch {
                            $uso = Join-Path $env:SystemRoot 'System32\UsoClient.exe'
                            if (Test-Path -LiteralPath $uso) { Start-Process -FilePath $uso -ArgumentList 'StartScan' -WindowStyle Hidden; 'WU scan triggered (UsoClient StartScan)' }
                            else { 'WU scan NOT triggered (no Scheduled Start task / UsoClient on this build)' }
                        }
                    }
                    $icw = @{ ComputerName=$Computer; ScriptBlock=$wuSb; Authentication='Negotiate'; SessionOption=$so; ErrorAction='Stop' }
                    if ($credSet) { $icw.Credential = $Cred }
                    $wuOut = ''
                    try { $wuOut = [string](Invoke-Command @icw) } catch { $wuOut = "WU trigger error: $($_.Exception.Message)" }
                    $detailParts += $wuOut
                }
                # Optional SCCM/MECM client refresh: trigger the client schedule cycles (ported
                # from $sbApply) so an assigned Software Center deployment surfaces. Best-effort -
                # a trigger failure never fails the pin. $cycles passed as ONE positional arg
                # via @(,$Cycles) so the GUID array is not splatted into many params.
                if ($SccmRefresh) {
                    & $pushStep 'SCCM' 'Pinned; triggering SCCM client schedule cycles...'
                    $sccmSb = {
                        param($cycles)
                        try {
                            $svc = Get-Service -Name CcmExec -ErrorAction Stop
                            if ($svc.Status -eq 'Running') {
                                foreach ($id in $cycles) {
                                    try { Invoke-CimMethod -Namespace 'root\ccm' -ClassName SMS_Client -MethodName TriggerSchedule -Arguments @{ sScheduleID=$id } -ErrorAction Stop | Out-Null } catch { }
                                }
                                'SCCM client cycles triggered'
                            } else { 'SCCM client present but not running' }
                        } catch { 'SCCM client (CcmExec) not found' }
                    }
                    $ics = @{ ComputerName=$Computer; ScriptBlock=$sccmSb; ArgumentList=@(,$Cycles); Authentication='Negotiate'; SessionOption=$so; ErrorAction='Stop' }
                    if ($credSet) { $ics.Credential = $Cred }
                    $sccmOut = ''
                    try { $sccmOut = [string](Invoke-Command @ics) } catch { $sccmOut = "SCCM refresh error: $($_.Exception.Message)" }
                    $detailParts += $sccmOut
                }
                $detailParts += 'Reboot target, then run Check for updates.'
                $r.Status = 'DONE'; $r.Detail = ($detailParts -join ' | '); $r.Ok = $true
            }

            'Unpin' {
                if ($DryRun) {
                    $wouldU = if ($RemoveBypass) { 'Would remove the Target Release Version policy AND the CPU/TPM bypass key' } else { 'Would remove the Target Release Version policy' }
                    $r.Status = 'DRY-RUN'; $r.Detail = "$wouldU ($authNote)."; $r.Ok = $true; break
                }
                $unpinNote = if ($RemoveBypass) { 'Removing TargetReleaseVersion policy + CPU/TPM bypass...' } else { 'Removing TargetReleaseVersion policy...' }
                & $pushStep 'Unpinning' $unpinNote
                # $removeBypass appended at the END of the remote param() (matches the call-site
                # ArgumentList order). Bypass removal copied EXACTLY from the reference $sbClear
                # (lines 851-858): key HKLM:\SYSTEM\Setup\MoSetup, value AllowUpgradesWithUnsupportedTPMOrCPU.
                $sb = {
                    param($removeBypass)
                    $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
                    if (Test-Path $regPath) {
                        Remove-ItemProperty -Path $regPath -Name 'TargetReleaseVersion'     -ErrorAction SilentlyContinue
                        Remove-ItemProperty -Path $regPath -Name 'ProductVersion'           -ErrorAction SilentlyContinue
                        Remove-ItemProperty -Path $regPath -Name 'TargetReleaseVersionInfo' -ErrorAction SilentlyContinue
                        $remaining = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).PSObject.Properties |
                            Where-Object { $_.Name -notlike 'PS*' }
                        if (-not $remaining) {
                            Remove-Item -Path $regPath -Force -ErrorAction SilentlyContinue
                            $msg = 'policy values removed; empty WindowsUpdate key removed'
                        } else {
                            $msg = 'policy values removed; key kept (other values present)'
                        }
                    } else {
                        $msg = 'policy key not present (nothing to remove)'
                    }
                    if ($removeBypass) {
                        $moKey = 'HKLM:\SYSTEM\Setup\MoSetup'
                        if (Test-Path $moKey) {
                            $moVal = Get-ItemProperty -Path $moKey -Name 'AllowUpgradesWithUnsupportedTPMOrCPU' -ErrorAction SilentlyContinue
                            if ($moVal -and $moVal.AllowUpgradesWithUnsupportedTPMOrCPU -eq 1) {
                                Remove-ItemProperty -Path $moKey -Name 'AllowUpgradesWithUnsupportedTPMOrCPU' -ErrorAction SilentlyContinue
                                $msg += '; bypass key removed'
                            } else { $msg += '; bypass was not set' }
                        } else { $msg += '; bypass was not set' }
                    }
                    $msg
                }
                $so = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 60000 -CancelTimeout 5000
                $ic = @{ ComputerName=$Computer; ScriptBlock=$sb; ArgumentList=@($RemoveBypass); Authentication='Negotiate'; SessionOption=$so; ErrorAction='Stop' }
                if ($credSet) { $ic.Credential = $Cred }
                $out = Invoke-Command @ic
                $r.Status = 'DONE'; $r.Detail = "$out"; $r.Ok = $true
            }

            'InstallCab' {
                if ($DryRun) {
                    $rb = if ($Reboot) { 'then reboot (10s)' } else { 'no reboot' }
                    $r.Status = 'DRY-RUN'; $r.Detail = "Would copy $CabName to C:\Temp and run DISM /Add-Package; $rb ($authNote)."; $r.Ok = $true; break
                }
                # OperationTimeout 0 = no per-operation cap (DISM can run for minutes).
                $so = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 0 -IdleTimeout 1800000 -CancelTimeout 5000
                $sp = @{ ComputerName=$Computer; Authentication='Negotiate'; SessionOption=$so; ErrorAction='Stop' }
                if ($credSet) { $sp.Credential = $Cred }
                $session = New-PSSession @sp
                try {
                    & $pushStep 'Copying' "Copying $CabName to C:\Temp on the target..."
                    Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
                        if (-not (Test-Path -Path 'C:\Temp')) { New-Item -Path 'C:\Temp' -ItemType Directory -ErrorAction Stop | Out-Null }
                    }
                    # When the operator typed a UNC share path, have the TARGET pull the package
                    # from the share inside the session (operator credential) instead of base64-
                    # streaming it from the admin box over WS-Man - the latter saturates the admin
                    # uplink under parallel installs. The share->target hop is a second hop, so on
                    # ANY error (e.g. Negotiate double-hop) fall back to the proven -ToSession push
                    # so behavior is never worse than before.
                    $pulledFromShare = $false
                    if ($CabFromShare) {
                        try {
                            Invoke-Command -Session $session -ArgumentList $CabPath, $CabName -ErrorAction Stop -ScriptBlock {
                                param($src, $nm)
                                Copy-Item -LiteralPath $src -Destination (Join-Path 'C:\Temp' $nm) -Force -ErrorAction Stop
                            }
                            $pulledFromShare = $true
                        } catch { $pulledFromShare = $false }
                    }
                    if (-not $pulledFromShare) {
                        Copy-Item -Path $CabPath -Destination 'C:\Temp\' -ToSession $session -Force -ErrorAction Stop
                    }

                    & $pushStep 'DISM' 'DISM /Online /Add-Package (this can run for minutes)...'
                    $res = Invoke-Command -Session $session -ArgumentList $CabName -ScriptBlock {
                        param($name)
                        $cab = Join-Path 'C:\Temp' $name
                        $o = @{ ExitCode = $null; Output = ''; Error = '' }
                        try {
                            $psi = New-Object System.Diagnostics.ProcessStartInfo
                            $psi.FileName               = 'dism.exe'
                            $psi.Arguments              = "/Online /Add-Package /PackagePath:`"$cab`" /Quiet /NoRestart"
                            $psi.UseShellExecute        = $false
                            $psi.RedirectStandardOutput = $true
                            $psi.RedirectStandardError  = $true
                            $psi.CreateNoWindow         = $true
                            $proc = [System.Diagnostics.Process]::Start($psi)
                            $stdout = $proc.StandardOutput.ReadToEnd()
                            $stderr = $proc.StandardError.ReadToEnd()
                            $proc.WaitForExit()
                            $o.ExitCode = $proc.ExitCode
                            $o.Output   = ($stdout + $stderr).Trim()
                        } catch { $o.Error = $_.Exception.Message }
                        return $o
                    }

                    if ($res.Error) {
                        $r.Status = 'FAILED'; $r.Detail = "DISM launch error: $($res.Error)"
                    }
                    elseif ($res.ExitCode -eq 0 -or $res.ExitCode -eq 3010) {
                        # exit 3010 = package staged but a reboot is REQUIRED to activate it; exit 0
                        # = fully applied, no reboot needed. A staged-but-not-rebooted box, or a box
                        # whose reboot failed to issue, is NOT really DONE - it gets the distinct
                        # 'NEEDS REBOOT' status (Ok stays $true: the package is installed) so the
                        # operator does not mistake an amber "still needs a manual reboot" box for a
                        # finished green one when scanning a large fleet.
                        $needsReboot = ($res.ExitCode -eq 3010)
                        $note = if ($needsReboot) { 'installed (reboot required)' } else { 'installed (exit 0)' }
                        if ($Reboot -and -not (& $isCancelled)) {
                            & $pushStep 'Rebooting' 'Install OK; issuing reboot (10s)...'
                            # Delayed reboot via shutdown.exe (ProcessStartInfo so we capture its
                            # real exit code); /t 10 lets the WinRM call return before the box drops.
                            try {
                                $rbres = Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
                                    $o = @{ ExitCode = $null; Error = '' }
                                    try {
                                        $psi = New-Object System.Diagnostics.ProcessStartInfo
                                        $psi.FileName               = 'shutdown.exe'
                                        $psi.Arguments              = '/r /t 10 /f /c "JANET Web Windows Upgrade: feature update installed"'
                                        $psi.UseShellExecute        = $false
                                        $psi.RedirectStandardOutput = $true
                                        $psi.RedirectStandardError  = $true
                                        $psi.CreateNoWindow         = $true
                                        $proc = [System.Diagnostics.Process]::Start($psi)
                                        $sout = $proc.StandardOutput.ReadToEnd()
                                        $serr = $proc.StandardError.ReadToEnd()
                                        $proc.WaitForExit()
                                        $o.ExitCode = $proc.ExitCode
                                        if ($proc.ExitCode -ne 0) { $o.Error = ($sout + $serr).Trim() }
                                    } catch { $o.Error = $_.Exception.Message }
                                    return $o
                                }
                                if ($rbres.ExitCode -eq 0) { $r.Status = 'DONE'; $r.Detail = "$CabName $note; reboot issued (10s)"; $r.Ok = $true }
                                else { $r.Status = 'NEEDS REBOOT'; $r.Detail = "$CabName $note; REBOOT FAILED (shutdown exit $($rbres.ExitCode)): $($rbres.Error)"; $r.Ok = $true }
                            } catch {
                                $r.Status = 'NEEDS REBOOT'; $r.Detail = "$CabName $note; REBOOT FAILED to issue: $($_.Exception.Message)"; $r.Ok = $true
                            }
                        }
                        elseif ($Reboot -and (& $isCancelled)) {
                            if ($needsReboot) { $r.Status = 'NEEDS REBOOT' } else { $r.Status = 'DONE' }
                            $r.Detail = "$CabName $note; REBOOT SKIPPED (cancelled)"; $r.Ok = $true
                        }
                        else {
                            if ($needsReboot) { $r.Status = 'NEEDS REBOOT'; $r.Detail = "$CabName $note"; $r.Ok = $true }
                            else { $r.Status = 'DONE'; $r.Detail = "$CabName $note"; $r.Ok = $true }
                        }
                    }
                    else {
                        $msg = [string]$res.Output
                        if ($msg.Length -gt 400) { $msg = $msg.Substring(0, 400) }
                        $r.Status = 'FAILED'; $r.Detail = "DISM exit $($res.ExitCode): $msg"
                    }
                }
                finally {
                    if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
                }
            }

            'CheckUpgrade' {
                # Read-only: pull setuperr.log from the failed in-place upgrade and classify it.
                # DryRun is meaningless here (nothing is changed), so it always just reads.
                & $pushStep 'Reading' 'Reading setuperr.log...'
                $sb = {
                    $log = 'C:\$WINDOWS.~BT\Sources\Panther\setuperr.log'
                    if (-not (Test-Path -LiteralPath $log)) { return [pscustomobject]@{ Code = 'NOLOG'; Line = '' } }
                    # setuperr.log can be held open during an in-flight upgrade; open shared.
                    $text = ''
                    $sr = $null
                    try {
                        $fs = [System.IO.File]::Open($log, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                        try { $sr = New-Object System.IO.StreamReader($fs); $text = $sr.ReadToEnd() } finally { if ($sr) { $sr.Dispose() }; $fs.Dispose() }
                    } catch {
                        try { $text = Get-Content -LiteralPath $log -Raw -ErrorAction Stop } catch { return [pscustomobject]@{ Code = 'READERR'; Line = $_.Exception.Message } }
                    }
                    if ([string]::IsNullOrWhiteSpace($text)) { return [pscustomobject]@{ Code = 'CLEAN'; Line = '' } }
                    $lines = @($text -split '\r?\n' | Where-Object { $_ -match '\S' })
                    # Out-of-memory build failure the page-file fix resolves: E_OUTOFMEMORY 0x8007000E,
                    # or an explicit out/insufficient-memory phrase in a setup error line.
                    $oom = $lines | Where-Object { $_ -match '0x8007000E' -or $_ -match '(?i)out of memory' -or $_ -match '(?i)insufficient memory' } | Select-Object -Last 1
                    if ($oom) { return [pscustomobject]@{ Code = 'OOM'; Line = ([string]$oom).Trim() } }
                    return [pscustomobject]@{ Code = 'ERRORS'; Line = ([string]($lines | Select-Object -Last 1)).Trim() }
                }
                $so = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 60000 -CancelTimeout 5000
                $ic = @{ ComputerName=$Computer; ScriptBlock=$sb; Authentication='Negotiate'; SessionOption=$so; ErrorAction='Stop' }
                if ($credSet) { $ic.Credential = $Cred }
                $res = Invoke-Command @ic
                $line = [string]$res.Line
                if ($line.Length -gt 300) { $line = $line.Substring(0, 300) }
                switch ([string]$res.Code) {
                    'OOM'     { $r.Status = 'MEMORY'; $r.Detail = "Out-of-memory build failure (0x8007000E) - run Set Page File, then re-run the upgrade. $line"; $r.Ok = $true }
                    'ERRORS'  { $r.Status = 'ERRORS'; $r.Detail = "setuperr.log last error: $line"; $r.Ok = $true }
                    'CLEAN'   { $r.Status = 'CLEAN';  $r.Detail = 'setuperr.log present, no error lines.'; $r.Ok = $true }
                    'NOLOG'   { $r.Status = 'NO LOG'; $r.Detail = 'No C:\$WINDOWS.~BT\Sources\Panther\setuperr.log (no recent in-place upgrade attempt).'; $r.Ok = $true }
                    'READERR' { $r.Status = 'FAILED'; $r.Detail = "Could not read setuperr.log: $line"; $r.Ok = $false }
                    default   { $r.Status = 'FAILED'; $r.Detail = 'Unknown check result.'; $r.Ok = $false }
                }
            }

            'SetPageFile' {
                $mb = $SizeMb
                if ($mb -lt 1024)   { $mb = 1024 }
                if ($mb -gt 131072) { $mb = 131072 }
                if ($DryRun) {
                    $rb = if ($Reboot) { 'then reboot (10s)' } else { 'no reboot (apply on next restart)' }
                    $r.Status = 'DRY-RUN'; $r.Detail = "Would disable automatic page-file management and set C: page file to $mb MB (fixed); $rb ($authNote)."; $r.Ok = $true; break
                }
                & $pushStep 'PageFile' "Disabling auto-manage and setting C: page file to $mb MB..."
                $sb = {
                    param($mb)
                    $notes = New-Object System.Collections.ArrayList
                    $cs = Get-WmiObject -Class Win32_ComputerSystem -EnableAllPrivileges -ErrorAction Stop
                    if ($cs.AutomaticManagedPagefile) {
                        $cs.AutomaticManagedPagefile = $false
                        [void]$cs.Put()
                        [void]$notes.Add('automatic management disabled')
                    } else {
                        [void]$notes.Add('automatic management already off')
                    }
                    # -EnableAllPrivileges on BOTH WMI calls: page-file create/resize needs
                    # SeCreatePagefilePrivilege, which WMI leaves present-but-disabled in the
                    # token unless explicitly enabled - without it the Put()/create fails
                    # access-denied AFTER auto-manage was already turned off (worst case: no
                    # usable page file at next boot).
                    $pf = Get-WmiObject -Class Win32_PageFileSetting -Filter "Name='C:\\pagefile.sys'" -EnableAllPrivileges -ErrorAction SilentlyContinue
                    if (-not $pf) {
                        [void](Set-WmiInstance -Class Win32_PageFileSetting -Arguments @{ Name = 'C:\pagefile.sys'; InitialSize = $mb; MaximumSize = $mb } -EnableAllPrivileges -ErrorAction Stop)
                        [void]$notes.Add("created C: page file at $mb MB")
                    } else {
                        $pf.InitialSize = $mb
                        $pf.MaximumSize = $mb
                        [void]$pf.Put()
                        [void]$notes.Add("C: page file set to $mb MB (fixed)")
                    }
                    ($notes -join '; ')
                }
                $so = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 120000 -CancelTimeout 5000
                $ic = @{ ComputerName=$Computer; ScriptBlock=$sb; ArgumentList=@($mb); Authentication='Negotiate'; SessionOption=$so; ErrorAction='Stop' }
                if ($credSet) { $ic.Credential = $Cred }
                $out = [string](Invoke-Command @ic)
                if ($Reboot -and -not (& $isCancelled)) {
                    & $pushStep 'Rebooting' 'Page file set; issuing reboot (10s)...'
                    try {
                        $icr = @{ ComputerName=$Computer; Authentication='Negotiate'; SessionOption=$so; ErrorAction='Stop' }
                        if ($credSet) { $icr.Credential = $Cred }
                        $rbres = Invoke-Command @icr -ScriptBlock {
                            $o = @{ ExitCode = $null; Error = '' }
                            try {
                                $psi = New-Object System.Diagnostics.ProcessStartInfo
                                $psi.FileName               = 'shutdown.exe'
                                $psi.Arguments              = '/r /t 10 /f /c "JANET Web Windows Upgrade: page file resized"'
                                $psi.UseShellExecute        = $false
                                $psi.RedirectStandardOutput = $true
                                $psi.RedirectStandardError  = $true
                                $psi.CreateNoWindow         = $true
                                $proc = [System.Diagnostics.Process]::Start($psi)
                                $sout = $proc.StandardOutput.ReadToEnd()
                                $serr = $proc.StandardError.ReadToEnd()
                                $proc.WaitForExit()
                                $o.ExitCode = $proc.ExitCode
                                if ($proc.ExitCode -ne 0) { $o.Error = ($sout + $serr).Trim() }
                            } catch { $o.Error = $_.Exception.Message }
                            return $o
                        }
                        if ($rbres.ExitCode -eq 0) { $r.Status = 'DONE'; $r.Detail = "$out; reboot issued (10s)"; $r.Ok = $true }
                        else { $r.Status = 'NEEDS REBOOT'; $r.Detail = "$out; REBOOT FAILED (shutdown exit $($rbres.ExitCode)): $($rbres.Error). Reboot manually to apply."; $r.Ok = $true }
                    } catch {
                        $r.Status = 'NEEDS REBOOT'; $r.Detail = "$out; REBOOT FAILED to issue: $($_.Exception.Message). Reboot manually to apply."; $r.Ok = $true
                    }
                }
                elseif ($Reboot -and (& $isCancelled)) {
                    $r.Status = 'NEEDS REBOOT'; $r.Detail = "$out; REBOOT SKIPPED (cancelled). Reboot manually to apply."; $r.Ok = $true
                }
                else {
                    $r.Status = 'NEEDS REBOOT'; $r.Detail = "$out; reboot required to apply the new size."; $r.Ok = $true
                }
            }

            'Diagnose' {
                # Read-only comprehensive 24H2 compatibility + WU health scan. The remote
                # scriptblock body is ported VERBATIM from the desktop $sbDiagnostic
                # (References\24h2script.ps1 lines 352-638); it returns a multi-line report
                # string. DryRun is meaningless (nothing changes) so it always just reads.
                # Constants fed via the appended worker params ($CpuPatterns/$MinRAM/$MinDisk/$MinTPM).
                & $pushStep 'Scanning' 'Running read-only diagnostic scan...'
                $sb = {
                    param($cpuPatterns, $minRAM, $minDisk, $minTPM)
                    $lines = @()

                    # ===== SECTION: SYSTEM INFO =====
                    $lines += "=== SYSTEM INFO ==="
                    $os = Get-CimInstance Win32_OperatingSystem
                    $cs = Get-CimInstance Win32_ComputerSystem
                    $lines += "[INFO] Hostname    : $($env:COMPUTERNAME)"
                    $lines += "[INFO] OS          : $($os.Caption) (Build $($os.BuildNumber))"
                    $lines += "[INFO] Model       : $($cs.Manufacturer) $($cs.Model)"

                    # Already on 24H2?
                    # 24H2 = Build 26100
                    if ([int]$os.BuildNumber -ge 26100) {
                        $lines += "[PASS] Already on 24H2 or newer (Build $($os.BuildNumber)) - no action needed"
                    } else {
                        $lines += "[INFO] Not yet on 24H2 (current build $($os.BuildNumber), need 26100+)"
                    }

                    # ===== SECTION: HARDWARE COMPATIBILITY =====
                    $lines += ""
                    $lines += "=== HARDWARE COMPATIBILITY ==="

                    # CPU
                    $cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
                    $cpuSupported = $false
                    foreach ($pattern in $cpuPatterns) {
                        if ($cpu -match $pattern) { $cpuSupported = $true; break }
                    }
                    if ($cpuSupported) { $lines += "[PASS] CPU         : $cpu" }
                    else { $lines += "[FAIL] CPU         : $cpu (not in supported list - bypass may be needed)" }

                    # TPM
                    $tpmPass = $false; $tpmVer = "Not found"
                    try {
                        $tpm = Get-CimInstance -Namespace "root\cimv2\Security\MicrosoftTpm" -ClassName Win32_Tpm -ErrorAction Stop
                        if ($tpm) {
                            $tpmVer = ($tpm.SpecVersion -split ",")[0].Trim()
                            if ([version]$tpmVer -ge [version]$minTPM) { $tpmPass = $true }
                        }
                    } catch { }
                    if ($tpmPass) { $lines += "[PASS] TPM         : v$tpmVer" }
                    else { $lines += "[FAIL] TPM         : v$tpmVer (need $minTPM+ - bypass may be needed)" }

                    # Secure Boot
                    $sbPass = $false
                    try { $sbState = Confirm-SecureBootUEFI -ErrorAction Stop; $sbPass = $sbState -eq $true } catch { }
                    if ($sbPass) { $lines += "[PASS] Secure Boot : Enabled" }
                    else { $lines += "[FAIL] Secure Boot : Disabled or unsupported" }

                    # RAM
                    $ramGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
                    if ($ramGB -ge $minRAM) { $lines += "[PASS] RAM         : ${ramGB} GB (need ${minRAM}+ GB)" }
                    else { $lines += "[FAIL] RAM         : ${ramGB} GB (need ${minRAM}+ GB)" }

                    # Disk
                    $sysDrive = $env:SystemDrive
                    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$sysDrive'"
                    $freeGB = [math]::Round($disk.FreeSpace / 1GB, 1)
                    $totalGB = [math]::Round($disk.Size / 1GB, 1)
                    if ($freeGB -ge $minDisk) { $lines += "[PASS] Disk        : ${freeGB} GB free / ${totalGB} GB total on $sysDrive" }
                    else { $lines += "[FAIL] Disk        : ${freeGB} GB free / ${totalGB} GB total on $sysDrive (need ${minDisk}+ GB free)" }

                    # ===== SECTION: REGISTRY STATE =====
                    $lines += ""
                    $lines += "=== REGISTRY STATE ==="

                    # Target release version policy
                    $wuPol = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
                    if (Test-Path $wuPol) {
                        $p = Get-ItemProperty -Path $wuPol -ErrorAction SilentlyContinue
                        if ($p.TargetReleaseVersion -eq 1) {
                            $lines += "[PASS] Target Release Policy : Product=$($p.ProductVersion) Version=$($p.TargetReleaseVersionInfo) (enabled)"
                        } else {
                            $lines += "[WARN] Target Release Policy : exists but TargetReleaseVersion != 1 (not active)"
                        }
                    } else {
                        $lines += "[WARN] Target Release Policy : NOT SET (Apply will set this)"
                    }

                    # CPU/TPM bypass
                    $moKey = "HKLM:\SYSTEM\Setup\MoSetup"
                    $bypassActive = $false
                    if (Test-Path $moKey) {
                        $moVal = Get-ItemProperty -Path $moKey -Name "AllowUpgradesWithUnsupportedTPMOrCPU" -ErrorAction SilentlyContinue
                        if ($moVal -and $moVal.AllowUpgradesWithUnsupportedTPMOrCPU -eq 1) { $bypassActive = $true }
                    }
                    if ($bypassActive) { $lines += "[INFO] CPU/TPM Bypass : ACTIVE (AllowUpgradesWithUnsupportedTPMOrCPU=1)" }
                    elseif (-not $cpuSupported -or -not $tpmPass) { $lines += "[WARN] CPU/TPM Bypass : NOT SET (hardware failed checks - bypass may be needed)" }
                    else { $lines += "[INFO] CPU/TPM Bypass : Not set (not needed - hardware is compatible)" }

                    # ===== SECTION: DEFERRALS & BLOCKS =====
                    $lines += ""
                    $lines += "=== DEFERRALS & BLOCKS ==="
                    $blockersFound = $false

                    if (Test-Path $wuPol) {
                        # Feature update deferral days
                        $d = Get-ItemProperty -Path $wuPol -Name "DeferFeatureUpdatesPeriodInDays" -ErrorAction SilentlyContinue
                        if ($d -and $d.DeferFeatureUpdatesPeriodInDays -gt 0) {
                            $lines += "[BLOCK] DeferFeatureUpdatesPeriodInDays = $($d.DeferFeatureUpdatesPeriodInDays) (may delay 24H2)"
                            $blockersFound = $true
                        }

                        # DeferFeatureUpdates flag
                        $dfu = Get-ItemProperty -Path $wuPol -Name "DeferFeatureUpdates" -ErrorAction SilentlyContinue
                        if ($dfu -and $dfu.DeferFeatureUpdates -eq 1) {
                            $lines += "[BLOCK] DeferFeatureUpdates = 1 (feature updates deferred)"
                            $blockersFound = $true
                        }

                        # DisableDualScan
                        $dds = Get-ItemProperty -Path $wuPol -Name "DisableDualScan" -ErrorAction SilentlyContinue
                        if ($dds -and $dds.DisableDualScan -eq 1) {
                            $lines += "[BLOCK] DisableDualScan = 1 (device cannot check Microsoft Update alongside WSUS)"
                            $blockersFound = $true
                        }

                        # DoNotConnectToWindowsUpdateInternetLocations
                        $noinet = Get-ItemProperty -Path $wuPol -Name "DoNotConnectToWindowsUpdateInternetLocations" -ErrorAction SilentlyContinue
                        if ($noinet -and $noinet.DoNotConnectToWindowsUpdateInternetLocations -eq 1) {
                            $lines += "[BLOCK] DoNotConnectToWindowsUpdateInternetLocations = 1 (WSUS-only mode)"
                            $blockersFound = $true
                        }

                        # WUServer set (WSUS managed)
                        $wuServer = Get-ItemProperty -Path $wuPol -Name "WUServer" -ErrorAction SilentlyContinue
                        if ($wuServer -and $wuServer.WUServer) {
                            $lines += "[INFO] WSUS Server : $($wuServer.WUServer) (device is WSUS-managed)"
                        }

                        # Paused via policy
                        foreach ($valName in @("PausedFeatureDate","PausedFeatureStatus")) {
                            $pv = Get-ItemProperty -Path $wuPol -Name $valName -ErrorAction SilentlyContinue
                            if ($pv.$valName) {
                                $lines += "[BLOCK] Policy $valName = $($pv.$valName)"
                                $blockersFound = $true
                            }
                        }
                    }

                    # UX Settings pause
                    $wuUx = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
                    if (Test-Path $wuUx) {
                        foreach ($valName in @("PauseFeatureUpdatesStartTime","PauseFeatureUpdatesEndTime",
                                               "PauseUpdatesStartTime","PauseUpdatesExpiryTime")) {
                            $pv = Get-ItemProperty -Path $wuUx -Name $valName -ErrorAction SilentlyContinue
                            if ($pv.$valName) {
                                $lines += "[BLOCK] UX\$valName = $($pv.$valName)"
                                $blockersFound = $true
                            }
                        }
                        # FlightSettingsMaxPauseDays - not a block itself but relevant
                        $activeHours = Get-ItemProperty -Path $wuUx -Name "ActiveHoursStart" -ErrorAction SilentlyContinue
                        if ($activeHours) {
                            $ahEnd = Get-ItemProperty -Path $wuUx -Name "ActiveHoursEnd" -ErrorAction SilentlyContinue
                            $lines += "[INFO] Active Hours : $($activeHours.ActiveHoursStart):00 - $($ahEnd.ActiveHoursEnd):00"
                        }
                    }

                    if (-not $blockersFound) { $lines += "[PASS] No deferrals or policy blocks detected" }

                    # ===== SECTION: WINDOWS UPDATE HEALTH =====
                    $lines += ""
                    $lines += "=== WINDOWS UPDATE HEALTH ==="

                    # WU services
                    foreach ($svcName in @("wuauserv","bits","cryptSvc","UsoSvc")) {
                        try {
                            $svc = Get-Service -Name $svcName -ErrorAction Stop
                            $startType = (Get-CimInstance Win32_Service -Filter "Name='$svcName'" -ErrorAction SilentlyContinue).StartMode
                            if ($svc.Status -eq 'Running') {
                                $lines += "[PASS] Service $svcName : Running ($startType)"
                            } elseif ($svc.Status -eq 'Stopped' -and $startType -eq 'Manual') {
                                $lines += "[INFO] Service $svcName : Stopped (Manual start - normal)"
                            } else {
                                $lines += "[WARN] Service $svcName : $($svc.Status) ($startType)"
                            }
                        } catch {
                            $lines += "[WARN] Service $svcName : not found"
                        }
                    }

                    # SoftwareDistribution size
                    $sdPath = "$env:SystemRoot\SoftwareDistribution"
                    if (Test-Path $sdPath) {
                        try {
                            $sdSize = [math]::Round((Get-ChildItem -Path $sdPath -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB, 1)
                            if ($sdSize -gt 2000) {
                                $lines += "[WARN] SoftwareDistribution : ${sdSize} MB (large - may need cache clear)"
                            } else {
                                $lines += "[INFO] SoftwareDistribution : ${sdSize} MB"
                            }
                        } catch { $lines += "[INFO] SoftwareDistribution : present (size check failed)" }
                    }

                    # Existing .bak folders from previous resets
                    $baks = Get-ChildItem -Path $env:SystemRoot -Directory -Filter "SoftwareDistribution.bak*" -ErrorAction SilentlyContinue
                    if ($baks.Count -gt 0) {
                        $lines += "[INFO] Previous WU resets : $($baks.Count) SoftwareDistribution.bak folder(s) found"
                    }

                    # Last WU scan time
                    try {
                        $autoUpdate = Get-CimInstance -Namespace "root\ccm\SoftwareUpdates\UpdatesStore" -ClassName CCM_UpdateStatus -ErrorAction Stop | Select-Object -First 1
                        if ($autoUpdate) { $lines += "[INFO] Last SCCM update scan data present" }
                    } catch { }

                    # ===== SECTION: SCCM CLIENT =====
                    $lines += ""
                    $lines += "=== SCCM CLIENT ==="

                    try {
                        $svc = Get-Service -Name CcmExec -ErrorAction Stop
                        if ($svc.Status -eq 'Running') {
                            $lines += "[PASS] SCCM Client : Running"

                            # Client version
                            try {
                                $ccmVer = (Get-CimInstance -Namespace "root\ccm" -ClassName SMS_Client -ErrorAction Stop).ClientVersion
                                $lines += "[INFO] Client Version : $ccmVer"
                            } catch { }

                            # 24H2 deployment visibility
                            try {
                                $updates = Get-CimInstance -Namespace "root\ccm\ClientSDK" -ClassName CCM_SoftwareUpdate -ErrorAction SilentlyContinue |
                                    Where-Object { $_.Name -match "24H2" -or $_.Name -match "Feature update to Windows 11" }
                                if ($updates) {
                                    $lines += "[PASS] 24H2 Deployment : VISIBLE in Software Center ($($updates.Count) matching update(s))"
                                    foreach ($u in $updates) {
                                        $evalState = switch ($u.EvaluationState) {
                                            0 {"None"} 1 {"Available"} 2 {"Submitted"} 3 {"Detecting"}
                                            4 {"PreDownload"} 5 {"Downloading"} 6 {"WaitInstall"}
                                            7 {"Installing"} 8 {"PendingSoftReboot"} 9 {"PendingHardReboot"}
                                            10 {"WaitReboot"} 11 {"Verifying"} 12 {"InstallComplete"}
                                            13 {"Error"} 14 {"WaitServiceWindow"} 15 {"WaitUserLogon"}
                                            16 {"WaitUserLogoff"} 17 {"WaitJobUserLogon"} 18 {"WaitUserReconnect"}
                                            19 {"PendingUserLogoff"} 20 {"PendingUpdate"} 21 {"WaitingRetry"}
                                            22 {"WaitPresModeOff"} 23 {"WaitForOrchestration"}
                                            default {"Unknown($($u.EvaluationState))"}
                                        }
                                        $lines += "[INFO]   -> $($u.Name) | State: $evalState | PercentComplete: $($u.PercentComplete)%"
                                    }
                                } else {
                                    $lines += "[WARN] 24H2 Deployment : NOT visible in Software Center"
                                    $lines += "[WARN]   -> Device may not be in the SCCM target collection (server-side fix)"
                                    $lines += "[WARN]   -> Or SCCM policy has not refreshed yet (Apply will trigger refresh)"
                                }
                            } catch {
                                $lines += "[WARN] 24H2 Deployment : Could not query CCM_SoftwareUpdate"
                            }
                        } else {
                            $lines += "[WARN] SCCM Client : present but $($svc.Status)"
                        }
                    } catch {
                        $lines += "[INFO] SCCM Client : not installed (device may not be SCCM-managed)"
                    }

                    # ===== SECTION: RECOMMENDATIONS =====
                    $lines += ""
                    $lines += "=== RECOMMENDATIONS ==="

                    if ([int]$os.BuildNumber -ge 26100) {
                        $lines += "[REC] Already on 24H2 - no action needed"
                    } else {
                        $recs = @()
                        if (-not (Test-Path $wuPol) -or (Get-ItemProperty -Path $wuPol -ErrorAction SilentlyContinue).TargetReleaseVersion -ne 1) {
                            $recs += "Apply target release version policy (Step 2: Apply)"
                        }
                        if (-not $cpuSupported -or -not $tpmPass) {
                            if (-not $bypassActive) {
                                $recs += "Enable CPU/TPM bypass checkbox before Apply (hardware not compatible)"
                            }
                        }
                        if ($blockersFound) {
                            $recs += "Deferrals/blocks detected - try Force Discovery with Aggressive mode, or contact GPO admin"
                        }
                        if ($recs.Count -eq 0) {
                            $recs += "Run Apply (Step 2) to set policy and trigger scans"
                            $recs += "If 24H2 does not appear after Apply, run Force Discovery (Step 3)"
                        }
                        foreach ($r in $recs) { $lines += "[REC] $r" }
                    }

                    return ($lines -join "`n")
                }
                # SoftwareDistribution recursive size scan can be slow; give the op a wider cap.
                $so = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 180000 -CancelTimeout 5000
                $ic = @{ ComputerName=$Computer; ScriptBlock=$sb; ArgumentList=@($CpuPatterns,$MinRAM,$MinDisk,$MinTPM); Authentication='Negotiate'; SessionOption=$so; ErrorAction='Stop' }
                if ($credSet) { $ic.Credential = $Cred }
                $report = [string](Invoke-Command @ic)
                $r.Report = $report
                # Derive the one-word STATUS verdict + a short one-line summary from the report
                # markers (the ported scriptblock returns only the string). Precedence per spec:
                #   1. build >= 26100                               -> ON 24H2
                #   2. (CPU unsupported OR TPM<2.0) AND no bypass    -> HW INCOMPAT
                #   3. any [BLOCK] deferral/pause                    -> BLOCKED
                #   4. policy missing / TargetReleaseVersion != 1    -> NEEDS POLICY
                #   5. otherwise                                     -> READY
                $on24     = ($report -match '(?m)^\[PASS\] Already on 24H2')
                $cpuFail  = ($report -match '(?m)^\[FAIL\] CPU')
                $tpmFail  = ($report -match '(?m)^\[FAIL\] TPM')
                $bypassOn = ($report -match '(?m)^\[INFO\] CPU/TPM Bypass : ACTIVE')
                $hasBlock = ($report -match '(?m)^\[BLOCK\]')
                $policyOk = ($report -match '(?m)^\[PASS\] Target Release Policy')
                $buildM   = [regex]::Match($report, '\(Build (\d+)\)')
                $buildNum = if ($buildM.Success) { $buildM.Groups[1].Value } else { '?' }
                if     ($on24)                                       { $verdict = 'ON 24H2' }
                elseif (($cpuFail -or $tpmFail) -and -not $bypassOn) { $verdict = 'HW INCOMPAT' }
                elseif ($hasBlock)                                   { $verdict = 'BLOCKED' }
                elseif (-not $policyOk)                              { $verdict = 'NEEDS POLICY' }
                else                                                 { $verdict = 'READY' }
                $sum = New-Object System.Collections.ArrayList
                [void]$sum.Add("Build $buildNum")
                [void]$sum.Add($(if ($cpuFail) { 'CPU unsupported' } else { 'CPU ok' }))
                [void]$sum.Add($(if ($tpmFail) { 'TPM<2.0' } else { 'TPM ok' }))
                if ($bypassOn) { [void]$sum.Add('bypass ACTIVE') }
                [void]$sum.Add($(if ($policyOk) { 'policy set' } else { 'policy not set' }))
                if ($hasBlock) { [void]$sum.Add('deferral/block present') }
                $r.Status = $verdict; $r.Detail = ($sum -join ' | '); $r.Ok = $true
            }

            'ForceDiscovery' {
                # Force targets to re-check for the pinned feature update. Safe mode re-applies
                # policy + triggers SCCM/GPO/WU scans; aggressive mode ALSO resets the WU cache.
                # The remote scriptblock body is ported VERBATIM from the desktop
                # $sbForceDiscovery (References\24h2script.ps1 lines 678-820) and returns a
                # multi-line log string. DryRun changes NOTHING - it reports intended steps only.
                if ($DryRun) {
                    $steps = New-Object System.Collections.ArrayList
                    [void]$steps.Add("[DRY-RUN] Would re-apply the target release policy ($Product $Version)")
                    [void]$steps.Add("[DRY-RUN] Would report deferrals/pauses (safe mode does NOT remove them)")
                    [void]$steps.Add("[DRY-RUN] Would trigger the SCCM client schedule cycles")
                    [void]$steps.Add("[DRY-RUN] Would run gpupdate /force /target:computer")
                    [void]$steps.Add("[DRY-RUN] Would trigger a WU scan (DetectNow + UsoClient StartScan)")
                    if ($Aggressive) {
                        [void]$steps.Add("[DRY-RUN] AGGRESSIVE: would remove deferral/pause policy + UX values")
                        [void]$steps.Add("[DRY-RUN] AGGRESSIVE: would STOP WU services, rename SoftwareDistribution + catroot2,")
                        [void]$steps.Add("[DRY-RUN] AGGRESSIVE: re-register the WU DLLs, restart services, re-apply policy, re-scan")
                    }
                    $r.Report = ($steps -join "`n")
                    $r.Status = 'DRY-RUN'
                    $r.Detail = if ($Aggressive) { "Would force discovery (AGGRESSIVE reset) for $Product $Version ($authNote)." } else { "Would force discovery (safe) for $Product $Version ($authNote)." }
                    $r.Ok = $true
                    break
                }
                $fdMsg = if ($Aggressive) { 'Force discovery (AGGRESSIVE WU reset)...' } else { 'Force discovery (safe re-scan)...' }
                & $pushStep 'Forcing' $fdMsg
                $sb = {
                    param($product, $version, $cycles, $aggressive)
                    $log = @()

                    # ===== ALWAYS SAFE: Re-apply target release version policy =====
                    $wuPol = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
                    if (-not (Test-Path $wuPol)) { New-Item -Path $wuPol -Force | Out-Null }
                    New-ItemProperty -Path $wuPol -Name "TargetReleaseVersion"     -Value 1        -PropertyType DWord  -Force | Out-Null
                    New-ItemProperty -Path $wuPol -Name "ProductVersion"           -Value $product  -PropertyType String -Force | Out-Null
                    New-ItemProperty -Path $wuPol -Name "TargetReleaseVersionInfo" -Value $version  -PropertyType String -Force | Out-Null
                    $log += "Target release policy applied ($product $version)"

                    # ===== ALWAYS SAFE: Report deferrals =====
                    $deferFound = @()
                    if (Test-Path $wuPol) {
                        $d = Get-ItemProperty -Path $wuPol -Name "DeferFeatureUpdatesPeriodInDays" -ErrorAction SilentlyContinue
                        if ($d -and $d.DeferFeatureUpdatesPeriodInDays -gt 0) { $deferFound += "DeferDays=$($d.DeferFeatureUpdatesPeriodInDays)" }
                        $dds = Get-ItemProperty -Path $wuPol -Name "DisableDualScan" -ErrorAction SilentlyContinue
                        if ($dds -and $dds.DisableDualScan -eq 1) { $deferFound += "DisableDualScan=1" }
                        $dfu = Get-ItemProperty -Path $wuPol -Name "DeferFeatureUpdates" -ErrorAction SilentlyContinue
                        if ($dfu -and $dfu.DeferFeatureUpdates -eq 1) { $deferFound += "DeferFeatureUpdates=1" }
                    }
                    $wuUx = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
                    if (Test-Path $wuUx) {
                        foreach ($valName in @("PauseFeatureUpdatesStartTime","PauseFeatureUpdatesEndTime",
                                               "PauseUpdatesStartTime","PauseUpdatesExpiryTime")) {
                            $pv = Get-ItemProperty -Path $wuUx -Name $valName -ErrorAction SilentlyContinue
                            if ($pv.$valName) { $deferFound += "$valName=$($pv.$valName)" }
                        }
                    }
                    if ($deferFound.Count -gt 0 -and -not $aggressive) {
                        $log += "WARN: Deferrals detected (NOT removed in safe mode): $($deferFound -join ', ')"
                        $log += "WARN: Contact GPO/Intune admin or re-run with Aggressive mode"
                    } elseif ($deferFound.Count -gt 0 -and $aggressive) {
                        $log += "Deferrals detected - will remove in aggressive mode"
                    } else { $log += "No deferrals detected" }

                    # ===== ALWAYS SAFE: SCCM client cycles =====
                    try {
                        $svc = Get-Service -Name CcmExec -ErrorAction Stop
                        if ($svc.Status -eq 'Running') {
                            foreach ($id in $cycles) {
                                try { Invoke-CimMethod -Namespace "root\ccm" -ClassName SMS_Client -MethodName TriggerSchedule -Arguments @{ sScheduleID=$id } -ErrorAction Stop | Out-Null } catch { }
                            }
                            $log += "SCCM client cycles triggered"
                        } else { $log += "SCCM client present but not running" }
                    } catch { $log += "SCCM client not found" }

                    # ===== ALWAYS SAFE: GPO refresh =====
                    try { & gpupdate /force /target:computer 2>&1 | Out-Null; $log += "GPO refreshed" }
                    catch { $log += "WARN: GPO refresh failed" }

                    # ===== ALWAYS SAFE: WU scan triggers =====
                    try { (New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow(); $log += "WU scan triggered" }
                    catch { $log += "WARN: WU scan trigger failed: $($_.Exception.Message)" }
                    try { & UsoClient.exe StartScan 2>&1 | Out-Null; $log += "UsoClient StartScan triggered" }
                    catch { $log += "WARN: UsoClient failed" }

                    # ===== AGGRESSIVE MODE ONLY =====
                    if ($aggressive) {
                        $log += "--- AGGRESSIVE MODE ---"

                        # Remove deferrals from policy key
                        if (Test-Path $wuPol) {
                            foreach ($valName in @("DeferFeatureUpdatesPeriodInDays","DeferFeatureUpdates",
                                                   "PausedFeatureDate","PausedFeatureStatus","DisableDualScan")) {
                                $existing = Get-ItemProperty -Path $wuPol -Name $valName -ErrorAction SilentlyContinue
                                if ($existing.$valName -ne $null) {
                                    Remove-ItemProperty -Path $wuPol -Name $valName -ErrorAction SilentlyContinue
                                    $log += "Removed policy value: $valName"
                                }
                            }
                        }
                        # Remove UX pause settings
                        if (Test-Path $wuUx) {
                            foreach ($valName in @("PausedFeatureDate","PausedFeatureStatus",
                                                   "PauseFeatureUpdatesStartTime","PauseFeatureUpdatesEndTime",
                                                   "PauseUpdatesStartTime","PauseUpdatesExpiryTime",
                                                   "PauseQualityUpdatesStartTime","PauseQualityUpdatesEndTime")) {
                                $pv = Get-ItemProperty -Path $wuUx -Name $valName -ErrorAction SilentlyContinue
                                if ($pv.$valName) {
                                    Remove-ItemProperty -Path $wuUx -Name $valName -ErrorAction SilentlyContinue
                                    $log += "Removed UX setting: $valName"
                                }
                            }
                        }

                        # Stop WU services
                        $servicesToStop = @("wuauserv","bits","cryptSvc","msiserver")
                        foreach ($svcName in $servicesToStop) {
                            try { Stop-Service -Name $svcName -Force -ErrorAction Stop } catch { }
                        }
                        $log += "WU services stopped"

                        # Rename SoftwareDistribution and catroot2
                        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                        $sdPath = "$env:SystemRoot\SoftwareDistribution"
                        if (Test-Path $sdPath) {
                            try {
                                Rename-Item -Path $sdPath -NewName "SoftwareDistribution.bak_$timestamp" -Force -ErrorAction Stop
                                $log += "SoftwareDistribution renamed to .bak_$timestamp"
                            } catch { $log += "WARN: Could not rename SoftwareDistribution: $($_.Exception.Message)" }
                        }
                        $crPath = "$env:SystemRoot\System32\catroot2"
                        if (Test-Path $crPath) {
                            try {
                                Rename-Item -Path $crPath -NewName "catroot2.bak_$timestamp" -Force -ErrorAction Stop
                                $log += "catroot2 renamed to .bak_$timestamp"
                            } catch { $log += "WARN: Could not rename catroot2: $($_.Exception.Message)" }
                        }

                        # Re-register WU-specific DLLs only
                        $wuDlls = @(
                            "wuapi.dll","wuaueng.dll","wuaueng1.dll","wucltui.dll",
                            "wups.dll","wups2.dll","wuweb.dll","wucltux.dll",
                            "muweb.dll","wuwebv.dll","qmgr.dll","qmgrprxy.dll",
                            "wintrust.dll","initpki.dll","softpub.dll","dssenh.dll",
                            "rsaenh.dll","cryptdlg.dll","msxml3.dll","msxml6.dll"
                        )
                        $regCount = 0
                        foreach ($dll in $wuDlls) { & regsvr32.exe /s $dll 2>&1 | Out-Null; $regCount++ }
                        $log += "$regCount WU-specific DLLs re-registered"

                        # Restart WU services
                        foreach ($svcName in $servicesToStop) {
                            try { Start-Service -Name $svcName -ErrorAction Stop } catch { }
                        }
                        $log += "WU services restarted"

                        # Re-apply policy after cache clear
                        New-ItemProperty -Path $wuPol -Name "TargetReleaseVersion"     -Value 1        -PropertyType DWord  -Force | Out-Null
                        New-ItemProperty -Path $wuPol -Name "ProductVersion"           -Value $product  -PropertyType String -Force | Out-Null
                        New-ItemProperty -Path $wuPol -Name "TargetReleaseVersionInfo" -Value $version  -PropertyType String -Force | Out-Null
                        $log += "Target release policy re-applied after reset"

                        # Post-reset scans
                        try { (New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow() } catch { }
                        try { & UsoClient.exe StartScan 2>&1 | Out-Null } catch { }
                        $log += "Post-reset WU scans triggered"
                    }

                    return ($log -join "`n")
                }
                # Aggressive mode stops services + re-registers DLLs; no per-op cap (can run minutes).
                $so = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 0 -IdleTimeout 1800000 -CancelTimeout 5000
                $ic = @{ ComputerName=$Computer; ScriptBlock=$sb; ArgumentList=@($Product,$Version,$Cycles,$Aggressive); Authentication='Negotiate'; SessionOption=$so; ErrorAction='Stop' }
                if ($credSet) { $ic.Credential = $Cred }
                $report = [string](Invoke-Command @ic)
                $r.Report = $report
                $r.Status = if ($Aggressive) { 'RESET' } else { 'DONE' }
                $r.Detail = if ($Aggressive) { "Force discovery complete (AGGRESSIVE WU reset) for $Product $Version. Reboot target, then Check for updates." } else { "Force discovery complete (safe re-scan) for $Product $Version. Reboot target, then Check for updates." }
                $r.Ok = $true
            }
        }
    }
    catch {
        $r.Status = 'FAILED'; $r.Detail = $_.Exception.Message
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
    # $Params['__job']; its 'Cancel' flag lets a running fan-out break cooperatively.
    $cancelJob = $null
    if ($Params -and $Params.ContainsKey('__job')) { $cancelJob = $Params['__job'] }
    $cancelCheck = { if ($cancelJob) { try { [bool]$cancelJob['Cancel'] } catch { $false } } else { $false } }

    # Map the UI action id to the worker op.
    $op = switch ($ActionId) {
        'diagnose'       { 'Diagnose' }
        'pin'            { 'Pin' }
        'unpin'          { 'Unpin' }
        'forcediscovery' { 'ForceDiscovery' }
        'installcab'     { 'InstallCab' }
        'checkupgrade'   { 'CheckUpgrade' }
        'setpagefile'    { 'SetPageFile' }
        'ping'           { 'Ping' }
        default          { $null }
    }
    if (-not $op) { & $send @{ type='error'; text="Unknown action '$ActionId'." }; return @{ rows=@(); summary=@{} } }

    # Audit-action vocabulary the server logger accepts is EXACTLY 'TouchHost' or
    # 'VulnPatched' (any other value is rejected). Map each state-changing op to one;
    # the read-only Ping sweep maps to $null so it emits NO audit row (the desktop
    # twin likewise never records a ping as a logged action - it only grids it).
    #   Pin/Unpin = write/remove the WindowsUpdate TargetReleaseVersion policy -> a
    #               config-writing host touch -> 'TouchHost'.
    #   InstallCab = DISM /Add-Package feature-update install -> remediation -> 'VulnPatched'.
    #   SetPageFile = write the WMI page-file policy -> a config-writing host touch -> 'TouchHost'.
    #   ForceDiscovery = re-write policy + trigger SCCM/GPO/WU (and optionally reset WU) -> 'TouchHost'.
    #   CheckUpgrade / Diagnose = read-only harvest -> $null -> no audit (like Ping).
    $auditAction = switch ($op) {
        'Pin'            { 'TouchHost' }
        'Unpin'          { 'TouchHost' }
        'ForceDiscovery' { 'TouchHost' }
        'InstallCab'     { 'VulnPatched' }
        'SetPageFile'    { 'TouchHost' }
        default          { $null }
    }

    # Targets: split (with '#' comment stripping), then keep only valid host/IP tokens.
    $raw = ConvertTo-JanetHostList ([string]$Params['targets'])
    $targets = New-Object System.Collections.ArrayList
    $skipped = 0
    foreach ($t in $raw) { if (Test-JanetTargetToken $t) { [void]$targets.Add($t) } else { $skipped++ } }
    if ($skipped) { & $send @{ type='log'; level='warn'; text="Skipped $skipped invalid target name(s)." } }
    if ($targets.Count -eq 0) { & $send @{ type='log'; level='warn'; text='No valid targets.' }; return @{ rows=@(); summary=@{ total=0 } } }

    # Common options.
    $attemptOffline = ConvertTo-JanetBool $Params['attemptOffline'] $false
    $dryRun         = ConvertTo-JanetBool $Params['dryRun'] $false
    $reboot         = ConvertTo-JanetBool $Params['reboot'] $true
    $runWu          = ConvertTo-JanetBool $Params['runWu'] $false
    # v0.3.0 options: ForceDiscovery aggressive; Pin bypass + sccmRefresh; Unpin removeBypass
    # (removeBypass DEFAULTS to $true so an Unpin fully reverses a bypassed Pin).
    $aggressive     = ConvertTo-JanetBool $Params['aggressive'] $false
    $bypass         = ConvertTo-JanetBool $Params['bypass'] $false
    $sccmRefresh    = ConvertTo-JanetBool $Params['sccmRefresh'] $false
    $removeBypass   = ConvertTo-JanetBool $Params['removeBypass'] $true
    # Diagnose constants + SCCM cycle GUIDs (defined once at module scope, copied EXACTLY
    # from the reference) threaded to the worker via the ArgFactory tail.
    $cpuPatterns    = $script:WinUpgradeCpuPatterns
    $minRAM         = $script:WinUpgradeMinRAMGB
    $minDisk        = $script:WinUpgradeMinDiskGB
    $minTPM         = $script:WinUpgradeMinTPMVersion
    $cycles         = $script:WinUpgradeCycles
    $product        = if ($Params['product']) { ([string]$Params['product']).Trim() } else { 'Windows 11' }
    $version        = if ($Params['version']) { ([string]$Params['version']).Trim() } else { '24H2' }
    # SetPageFile size: default 16 GB, clamped 1-128 GB (worker re-clamps as a backstop).
    $sizeMb         = 16384
    if ($Params['sizeMb']) { $sm = 0; if ([int]::TryParse([string]$Params['sizeMb'], [ref]$sm)) { $sizeMb = $sm } }
    if ($sizeMb -lt 1024)   { $sizeMb = 1024 }
    if ($sizeMb -gt 131072) { $sizeMb = 131072 }
    # CAB source: a Browse/drag upload (server temp path) wins over a typed path.
    $cabUpload      = if ($Params['cabUpload']) { ([string]$Params['cabUpload']).Trim() } else { '' }
    $cabTyped       = if ($Params['cabPath'])   { ([string]$Params['cabPath']).Trim() }   else { '' }
    $cabPath        = if ($cabUpload) { $cabUpload } else { $cabTyped }
    $cabName        = ''
    # A Browse/drag upload always lands in a LOCAL server-temp dir, so only an
    # operator-typed UNC path (\\server\share\...) is eligible for the target-pull
    # fast path; everything else keeps the -ToSession push.
    $cabFromShare   = ((-not $cabUpload) -and ($cabTyped -like '\\*'))

    # Per-action validation + tuning.
    $defThreads    = 16
    $maxJobSeconds = 120
    if ($op -eq 'Ping')           { $defThreads = 32 }
    if ($op -eq 'CheckUpgrade')   { $defThreads = 16 }
    if ($op -eq 'Diagnose')       { $defThreads = 16; $maxJobSeconds = 180 }
    if ($op -eq 'SetPageFile')    { $defThreads = 8; $maxJobSeconds = 180 }
    if ($op -eq 'ForceDiscovery') { $defThreads = 8; $maxJobSeconds = 600 }
    if ($op -eq 'Pin') {
        if ([string]::IsNullOrWhiteSpace($product) -or [string]::IsNullOrWhiteSpace($version)) {
            & $send @{ type='log'; level='warn'; text='Product and Version are both required to pin a target release.' }
            return @{ rows=@(); summary=@{ total=$targets.Count } }
        }
    }
    if ($op -eq 'InstallCab') {
        $defThreads = 8
        $maxJobSeconds = 3600    # DISM feature-update install can run for minutes
        if (-not $dryRun) {
            if ([string]::IsNullOrWhiteSpace($cabPath) -or -not (Test-Path -LiteralPath $cabPath)) {
                & $send @{ type='log'; level='warn'; text="No CAB/MSU found. Enter a readable path or use Browse to upload one. ('$cabPath')" }
                return @{ rows=@(); summary=@{ total=$targets.Count } }
            }
        }
        if ($cabPath) { $cabName = Split-Path -Leaf $cabPath }
    }

    $threads = $defThreads
    if ($Params['threads']) {
        $tp = 0
        if ([int]::TryParse([string]$Params['threads'], [ref]$tp)) { $threads = $tp }
    }
    $threads = [Math]::Max(1, [Math]::Min(64, $threads))

    # ArgFactory: leading ',' wraps the arg list so the ONE pipeline unroll in the
    # BeginInvoke loop preserves each element (incl. the $cpuPatterns / $cycles arrays)
    # as a single positional argument. New v0.3.0 args appended at the END in the SAME
    # order as the appended worker param() tail (a mismatch silently corrupts every arg).
    $argFactory  = { param($h) ,@($h, $op, $Credential, $product, $version, $cabPath, $cabName, $cabFromShare, $reboot, $attemptOffline, $dryRun, $runWu, $sizeMb, $cancelJob, $stepQueue, $aggressive, $bypass, $sccmRefresh, $removeBypass, $cpuPatterns, $minRAM, $minDisk, $minTPM, $cycles) }
    $rowOf       = { param($res) @{ Host=$res.Host; Ping=[string]$res.Ping; Status=[string]$res.Status; Detail=[string]$res.Detail } }

    $modeNote  = if ($dryRun) { ' [DRY-RUN]' } else { '' }
    $authLabel = if ($Credential) { "as $($Credential.UserName)" } else { 'current session' }
    # Thread-safe step queue: the per-host worker enqueues live phase messages
    # (Copying / DISM / Rebooting); the harvest loop dequeues each pass and streams a
    # phase row so each host narrates its progress (parity with pkginstall + the desktop
    # "Copying.../Installing..." recolour). The final row, keyed by Host, replaces it.
    $stepQueue = [System.Collections.Concurrent.ConcurrentQueue[psobject]]::new()
    & $send @{ type='status'; text="Starting '$ActionId'$modeNote on $($targets.Count) host(s) with $threads thread(s)..." }
    # Persistent, timestamped START entry in the activity log (desktop-tool parity:
    # type='status' only updates the single transient status line and is overwritten;
    # type='log' lines accumulate as scrollback).
    & $send @{ type='log'; level='info'; text="[$(Get-Date -Format 'HH:mm:ss')] START '$ActionId'$modeNote on $($targets.Count) host(s) ($authLabel), $threads thread(s)." }

    $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $threads, $iss, $Host)
    $pool.Open()
    # seed Queued rows so the operator sees the whole target list immediately (ping is
    # instant, so it skips straight to Online/Offline rather than flashing Queued).
    if ($op -ne 'ping') { foreach ($h in $targets) { & $send (@{ type='row' } + @{ Host=$h; Ping=''; Status='Queued'; Detail='waiting for a runspace...' }) } }
    $jobs = New-Object System.Collections.ArrayList
    foreach ($h in $targets) {
        $ps = [powershell]::Create(); $ps.RunspacePool = $pool
        [void]$ps.AddScript($script:WinUpgradeWorker)
        foreach ($a in (& $argFactory $h)) { [void]$ps.AddArgument($a) }
        [void]$jobs.Add([pscustomobject]@{ Host=$h; PS=$ps; Async=$ps.BeginInvoke(); StartTime=(Get-Date) })
    }

    $rows = New-Object System.Collections.ArrayList
    $done = 0; $okCount = 0; $failCount = 0
    $stopHandles = New-Object System.Collections.ArrayList
    $cancelling  = $false
    $coopDeadline = [datetime]::MaxValue
    try {
        while ($done -lt $jobs.Count) {
            # paint the live phase steps (Copying / DISM / Rebooting) workers enqueued
            $msg = $null
            while ($stepQueue.TryDequeue([ref]$msg)) {
                & $send (@{ type='row' } + @{ Host=$msg.Hostname; Ping=''; Status=$msg.Step; Detail=$msg.Detail })
            }
            foreach ($j in $jobs) {
                if ($j.PS -and $j.Async.IsCompleted) {
                    $res = $null
                    try { $res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 } catch { $res = [ordered]@{ Host=$j.Host; Ping=''; Status='FAILED'; Detail="worker error: $($_.Exception.Message)"; Ok=$false } }
                    try { $j.PS.Dispose() } catch {}
                    $j.PS = $null
                    if ($null -eq $res) { $res = [ordered]@{ Host=$j.Host; Ping=''; Status='FAILED'; Detail='worker returned no result'; Ok=$false } }
                    $ok = [bool]$res.Ok
                    if ($ok) { $okCount++ } else { $failCount++ }
                    $row = & $rowOf $res
                    [void]$rows.Add($row)
                    & $send (@{ type='row' } + $row)
                    # Diagnose / ForceDiscovery return a full multi-line report on $res.Report;
                    # stream it to the activity log line-by-line, colour tags kept as text prefixes
                    # ([PASS]/[FAIL]/[WARN]/[BLOCK]/[REC]/[INFO], mirror of reference lines 884-895)
                    # that the VIEW colours. level is a best-effort hint only.
                    $rpt = ''
                    try { $rpt = [string]$res.Report } catch { $rpt = '' }
                    if ($rpt) {
                        & $send @{ type='log'; level='info'; text="----- $($res.Host) : $([string]$res.Status) -----" }
                        foreach ($ln in ($rpt -split "`r?`n")) {
                            if ([string]::IsNullOrWhiteSpace($ln)) { continue }
                            $lvl = 'info'
                            if     ($ln -match '^\s*\[FAIL\]' -or $ln -match '^\s*\[BLOCK\]') { $lvl = 'error' }
                            elseif ($ln -match '^\s*\[WARN\]' -or $ln -match '^\s*WARN:')     { $lvl = 'warn' }
                            & $send @{ type='log'; level=$lvl; text=$ln }
                        }
                    }
                    # One audit row per host per state-changing op, matching the depth
                    # at which the desktop twin records each result. $auditAction is $null
                    # only for the read-only Ping sweep -> no emit. Key the RESULT on $ok
                    # (not an exact status string) with a DRY-RUN/Skipped/Cancelled skip-set:
                    # those set Ok=$true but perform NO work, so they audit as 'Skipped' with
                    # itemCount=0 -- never a phantom Success. A real install success ('DONE'
                    # OR 'NEEDS REBOOT' - package staged, reboot pending) audits Success/1;
                    # everything else is a Failure/0.
                    if ($auditAction) {
                        $auditResult = if ('DRY-RUN','Skipped','Cancelled' -contains [string]$res.Status) { 'Skipped' } elseif ($ok) { 'Success' } else { 'Failure' }
                        $auditItems  = if ($auditResult -eq 'Success') { 1 } else { 0 }
                        & $send @{ type='audit'; action=$auditAction; target=$res.Host; result=$auditResult; itemCount=$auditItems; detail=([string]$res.Detail) }
                    }
                    $done++
                    & $send @{ type='progress'; done=$done; total=$jobs.Count }
                }
            }
            # Watchdog: a wedged host must not stall the run. BeginStop only (never
            # Dispose here - it blocks); the handle settles via EndStop in finally.
            foreach ($j in $jobs) {
                if ($j.PS -and -not $j.Async.IsCompleted -and ((Get-Date) - $j.StartTime).TotalSeconds -gt $maxJobSeconds) {
                    try { [void]$stopHandles.Add([pscustomobject]@{ PS=$j.PS; Handle=$j.PS.BeginStop($null, $null) }) } catch {}
                    $j.PS = $null
                    $failCount++; $done++
                    $trow = & $rowOf ([ordered]@{ Host=$j.Host; Ping=''; Status='FAILED'; Detail="Job timeout over ${maxJobSeconds}s"; Ok=$false })
                    [void]$rows.Add($trow)
                    & $send (@{ type='row' } + $trow)
                    # Abandon/timeout path for this host is still a failure of the
                    # state-changing op -> audit it (skip for the read-only Ping sweep).
                    if ($auditAction) { & $send @{ type='audit'; action=$auditAction; target=$j.Host; result='Failure'; itemCount=0; detail="Job timeout over ${maxJobSeconds}s" } }
                    & $send @{ type='log'; level='warn'; text="[$($j.Host)] TIMEOUT after ${maxJobSeconds}s - aborting" }
                    & $send @{ type='progress'; done=$done; total=$jobs.Count }
                }
            }
            if ($done -lt $jobs.Count) {
                if (-not $cancelling -and (& $cancelCheck)) {
                    $cancelling = $true
                    if ($cancelJob) { try { $cancelJob['Cancel'] = $true } catch {} }
                    $coopDeadline = (Get-Date).AddMilliseconds(8000)
                    & $send @{ type='log'; level='warn'; text='Cancelled by operator; signalling in-flight host(s) to stop cooperatively...' }
                }
                if ($cancelling -and (Get-Date) -ge $coopDeadline) {
                    foreach ($j in $jobs) {
                        if ($j.PS) {
                            try { [void]$stopHandles.Add([pscustomobject]@{ PS=$j.PS; Handle=$j.PS.BeginStop($null, $null) }) } catch {}
                            $j.PS = $null
                            $failCount++; $done++
                            $crow = & $rowOf ([ordered]@{ Host=$j.Host; Ping=''; Status='Cancelled'; Detail='cancelled by operator'; Ok=$false })
                            [void]$rows.Add($crow)
                            & $send (@{ type='row' } + $crow)
                            # Operator-cancel/force-stop path for this host -> audit the
                            # abandoned state-changing op (skip for the read-only Ping sweep).
                            if ($auditAction) { & $send @{ type='audit'; action=$auditAction; target=$j.Host; result='Failure'; itemCount=0; detail='cancelled by operator' } }
                        }
                    }
                    & $send @{ type='log'; level='warn'; text='Cancel grace elapsed; remaining host(s) force-stopped.' }
                    break
                }
                Start-Sleep -Milliseconds 120
            }
        }
    } finally {
        foreach ($sh in $stopHandles) {
            try { $sh.PS.EndStop($sh.Handle) } catch {}
            try { $sh.PS.Dispose() } catch {}
        }
        try { $pool.Close(); $pool.Dispose() }
        catch { & $send @{ type='log'; level='warn'; text="Runspace pool close error: $($_.Exception.Message)" } }
    }

    $skipNote = if ($skipped) { "  (Skipped $skipped invalid target name(s))" } else { '' }
    & $send @{ type='status'; text="Done$modeNote. $okCount ok, $failCount failed of $($jobs.Count)." }
    # Persistent FINISHED tally in the activity log (desktop-tool parity).
    & $send @{ type='log'; level='info'; text="[$(Get-Date -Format 'HH:mm:ss')] FINISHED$modeNote. OK=$okCount  Failed=$failCount  of $($jobs.Count).$skipNote" }
    return @{ rows = @($rows); summary = @{ total=$jobs.Count; ok=$okCount; failed=$failCount; skipped=$skipped } }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction
