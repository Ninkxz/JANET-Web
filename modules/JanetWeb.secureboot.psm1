# =============================================================================
#  JanetWeb.secureboot.psm1  -  Secure Boot Enabler engine for JANET Web
#
#  RE-FORKED from the desktop  Tools\SecureBootEnabler.ps1 (v1.5.0): the SYSTEM
#  $script:Payload (OEM BIOS branches + brick-safety precheck), the dry-run and
#  live per-host Start-Job scriptblocks, and the orchestration. WinForms dropped.
#  Cross-checked against JanetOne.secureboot.psm1 to keep its fixes (Lenovo Save
#  commit return capture, HP pending-reboot read-back, Dell non-zero Status as
#  error, corrupt-vs-C$-denied-vs-timeout discrimination, cooperative __job cancel).
#
#  Remotely enables UEFI Secure Boot on Dell / HP / Lenovo by dropping a SYSTEM-
#  ACL'd payload .ps1 onto each target's C$ admin share and running it through a
#  WinRM-armed SYSTEM scheduled task, then polling the JSON result off
#  the share. Fans out across hosts with the RunspacePool pattern, streaming rows.
#  audit 2026-07-24 (v1.6.8): the payload now SUSPENDS BITLOCKER for one reboot on
#  every TPM-sealed volume before the firmware write (a Secure Boot change re-measures
#  the boot PCRs, so an un-suspended host stops at the recovery-key prompt) and fails
#  CLOSED - a host whose suspend does not take is REFUSED, never written. Refusals
#  (BitLocker + the UEFI/GPT brick-safety stop) now carry their own 'Refused' status
#  and tally instead of riding out green as "already enabled".
#  audit 2026-07-25 (v1.6.9, fable re-audit follow-up): closed the ONE fail-OPEN corner
#  left in that guarantee - the cmdlets-absent manage-bde fallback used to proceed on a
#  throw / non-zero exit / empty or LOCALIZED output, so an unreadable state read as "no
#  protected volume". It now REFUSES anything it cannot positively parse as protection-off.
#  Also resumes BitLocker when the firmware write never happened (unsupported OEM or a
#  rejected OEM write) instead of costing the host an unprotected boot for nothing, and
#  fills the BitLocker cell on the early-error / timeout / cancel rows.
#
#  Contract (unchanged across the suite):
#    Get-JanetToolManifest                                         -> descriptors
#    Invoke-JanetToolAction -ActionId -Params -Credential -Emit     -> { rows; summary }
#  -Emit shapes: status / progress / row / log / audit. The bespoke view
#  (web/js/views/secureboot.view.js) owns presentation: a status-pill ResultsGrid
#  + a custom progress track, coloured per-host by Status from the row stream.
# =============================================================================

# loop76: shared error->actionable-hint mapper (why a host failed + how to fix it).
Import-Module (Join-Path $PSScriptRoot 'JanetWeb.troubleshoot.psm1') -Force -ErrorAction SilentlyContinue

function Get-JanetToolManifest {
    @{
        id       = 'secureboot'
        name     = 'Secure Boot Enabler'
        version  = '1.6.9'   # audit 2026-07-25 fable re-audit follow-up (manage-bde fallback fails CLOSED / resume-on-no-write / BitLocker cell on every row shape); Secureboot.BitLockerRefuse.Tests.ps1 pins it EXACTLY - bump both together
        category = 'Hardening'
        summary  = 'Two-stage Secure Boot hardening: (1) a READ-ONLY fleet-wide SCAN that fans out one WinRM probe per host (no 50-host cap) and returns a per-host verdict - ENABLED, READY TO ENABLE (off + UEFI + GPT + Dell/HP/Lenovo), OFF - UNSUPPORTED OEM, or BLOCKED - LEGACY/MBR - so the operator can hand the READY hosts straight to (2) the ENABLE action, which remotely enables UEFI Secure Boot on Dell, HP and Lenovo via a WinRM-armed SYSTEM scheduled task with a UEFI+GPT brick-safety precheck and dry-run preflight (waves of up to 50).'
        actions  = @(
            @{
                id          = 'scan-secure-boot'
                label       = 'Scan Secure Boot (Fleet)'
                description = 'READ-ONLY fleet-wide Secure Boot posture scan. One WinRM Invoke-Command round-trip per host (no C$ drop, no scheduled task, no firmware write) reads Secure Boot state (Confirm-SecureBootUEFI + SecureBoot registry corroboration), firmware type (UEFI/Legacy), the system disk partition style (GPT/MBR), manufacturer/model, BIOS version/date and OS build, then derives an admin-side verdict per host: ENABLED, READY TO ENABLE, OFF - UNSUPPORTED OEM, or BLOCKED - LEGACY/MBR. No host cap, no admin-session gate. Unreachable hosts soft-skip (OFFLINE); a stale-DNS wrong box soft-skips (DNS MISMATCH). Feed the READY-TO-ENABLE hosts to Enable Secure Boot in waves of up to 50.'
                kind        = 'stream-table'
                destructive = $false
                columns     = @('Host','Ping','Verdict','SecureBoot','Firmware','Disk','Manufacturer','Model','Detail')
                inputs      = @(
                    @{ name='targets';        label='Targets (one host per line)'; type='hostlist'; required=$true },
                    @{ name='attemptOffline'; label='Attempt even if offline (host unreachable)'; type='bool'; required=$false; default=$false },
                    @{ name='threads';        label='Parallel hosts (1-32)'; type='int'; required=$false; default=16 }
                )
            }
            @{
                id          = 'enable-secure-boot'
                label       = 'Enable Secure Boot'
                description = 'Enable Secure Boot across target machines with OEM-specific WMI payloads (Dell/HP/Lenovo). Validates UEFI+GPT boot safety, SUSPENDS BitLocker for one reboot on any TPM-sealed volume (a host whose suspend fails is REFUSED, never written), detects manufacturer, writes the firmware setting, and polls the result JSON from the C$ admin share. Dry Run does a TCP (5985/5986/445) reachability + WinRM manufacturer preflight only.'
                kind        = 'stream-table'
                destructive = $true
                confirm     = 'Write the UEFI Secure Boot firmware setting on the selected host(s)? Each enabled host is left PENDING A REBOOT; the JANET dispatcher is auto-excluded (self-guard), JANET skips any host it cannot confirm is on a safe UEFI+GPT boot path, and BitLocker is suspended for one reboot on TPM-sealed volumes (REFUSED if that suspend fails). A live run (not Dry Run) requires typing ENABLE to arm. Proceed?'
                columns     = @('Host','Status','Manufacturer','Before','After','SetResult','BitLocker','Error')
                inputs      = @(
                    @{ name='targets';            label='Targets (one host per line, max 50)'; type='hostlist'; required=$true },
                    @{ name='bios_password';      label='BIOS Password (no comma, quote or backtick)'; type='password'; required=$false },
                    @{ name='allowEmptyPassword'; label='Allow empty BIOS password (only if the BIOS has no password set)'; type='bool'; required=$false; default=$false },
                    @{ name='dry_run';            label='Dry Run (preflight only, no firmware write)'; type='bool'; required=$false; default=$false },
                    # audit 2026-07-24: secureboot was the ONLY module reading a 'confirm' param it never
                    # declared, so the typed-word gate at Invoke-JanetToolAction was invisible to the
                    # manifest-driven generic view / API caller. required=$false because Dry Run is
                    # deliberately ungated (mirrors restart.psm1's RESTART input).
                    @{ name='confirm';            label='Type ENABLE to arm (live firmware write only; dry run exempt)'; type='text'; required=$false },
                    @{ name='threads';            label='Parallel hosts (1-10)'; type='int'; required=$false; default=5 }
                )
            }
        )
    }
}

function ConvertTo-SecureBootHostList {
    # Split a pasted blob into clean, unique, upper-cased hostnames.
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return @() }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $out  = New-Object System.Collections.ArrayList
    foreach ($tok in ($Raw -split '[\r\n,;\t ]+')) {
        $h = $tok.Trim()
        # Accept only a bare host/IPv4 token; drop UNC/URL/junk before any remote call.
        if ($h -and ($h -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$') -and $seen.Add($h)) { [void]$out.Add($h.ToUpperInvariant()) }
    }
    return $out.ToArray()
}

# -----------------------------------------------------------------------------
# Self-guard (P2-6b): secureboot-local equivalent of JanetWeb.restart.psm1's
# Get-JanetLocalIdentity / Test-JanetHostIsSelf (audit#10). Deliberately NOT
# cross-imported from restart.psm1 - each engine module owns its own copy so
# they can load independently. Enabling Secure Boot leaves the target pending
# a reboot; if that target were the box running JANET, the eventual reboot
# (or a hung firmware write) could take the JANET server down mid-fleet-run.
# Set of identities that resolve to THIS dispatcher host: shortname, FQDN, all
# NIC IPs, and loopback. Computed once and cached. Case-insensitive HashSet.
# -----------------------------------------------------------------------------
function Get-JanetSbeLocalIdentity {
    if ($script:SbeLocalIdentity) { return ,$script:SbeLocalIdentity }
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($n in @($env:COMPUTERNAME, 'localhost', '127.0.0.1', '::1')) { if ($n) { [void]$set.Add($n) } }
    try { [void]$set.Add([System.Net.Dns]::GetHostName()) } catch {}
    try {
        $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
        if ($fqdn) { [void]$set.Add($fqdn); [void]$set.Add(($fqdn -split '\.')[0]) }
    } catch {}
    try { foreach ($ip in [System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME)) { [void]$set.Add($ip.IPAddressToString) } } catch {}
    # Also add every locally-BOUND unicast IPv4 (mgmt/OOB NICs, lagging DNS): a bound
    # IP not registered under this box's own name would otherwise be missed by the
    # DNS lookup above, letting a pasted IP-literal target slip past the self-guard.
    try {
        foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($nic.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up) { continue }
            foreach ($ua in $nic.GetIPProperties().UnicastAddresses) {
                if ($ua.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { [void]$set.Add($ua.Address.IPAddressToString) }
            }
        }
    } catch {}
    $script:SbeLocalIdentity = $set
    return ,$set   # comma stops PowerShell unrolling the HashSet (drops the OrdinalIgnoreCase comparer)
}

# True if a target token names this dispatcher host (short/FQDN/IP/loopback).
function Test-JanetSbeHostIsSelf {
    param([string]$Target)
    if ([string]::IsNullOrWhiteSpace($Target)) { return $false }
    $self = Get-JanetSbeLocalIdentity
    if ($self.Contains($Target)) { return $true }
    if ($Target -match '^127\.') { return $true }                      # any loopback literal
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Target, [ref]$ip)) {
        if ($self.Contains(($Target -split '\.')[0])) { return $true }  # shortname alias, hostnames only
    }
    return $false
}

# ----------------------------------------------------------------------------
# PAYLOAD - runs on the REMOTE machine as SYSTEM via scheduled task.
# $BIOSPassword and $ResultPath are prepended as variable assignments before
# this block is written to the target. Do NOT add a param() block here.
# Lifted verbatim from Tools\SecureBootEnabler.ps1 v1.5.0 ($script:Payload).
# ----------------------------------------------------------------------------
$script:SbePayload = @'
# $BIOSPassword and $ResultPath are injected by the launcher before this block

function New-Result {
    param($Mfr, $Current, $SetResult, $New, $Err = '')
    [PSCustomObject]@{
        Manufacturer = "$Mfr"
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
    # Idempotent re-run guard: Lenovo CurrentSetting is "SecureBoot,<value>[,...]"; the
    # value token is element [1]. If it ALREADY reads enabled yet the OS-booted-state gate
    # upstream did NOT short-circuit => the enable is already STAGED and the host is
    # PENDING REBOOT. Skip re-firing SetBiosSetting/SaveBiosSettings and report the
    # already-pending state instead of re-writing (and re-committing) the set value.
    $curVal = ''
    if ($current) { $cparts = "$current" -split ','; if ($cparts.Count -ge 2) { $curVal = $cparts[1].Trim() } }
    if ($curVal -match '^(?i)enable') {
        return New-Result -Mfr 'Lenovo' -Current $current -SetResult 'AlreadyPending' `
            -New "$current (already pending reboot)" -Err ''
    }
    $setRes   = (Get-WmiObject -Class Lenovo_SetBiosSetting -Namespace $ns -EA Stop
                ).SetBiosSetting("SecureBoot,Enable,$BIOSPassword,ascii,us").return
    # Commit - without this the setting reverts on next boot. Lenovo WMI methods
    # return the STRING 'Success' on success (not 0). Capture the commit return
    # too: discarding it meant a refused commit was reported as a clean Success
    # while the setting silently reverted on the next reboot.
    $saveRes  = (Get-WmiObject -Class Lenovo_SaveBiosSettings -Namespace $ns -EA Stop
                ).SaveBiosSettings("$BIOSPassword,ascii,us").return
    $new = (& $getSB).CurrentSetting
    # Compare the post-write read-back to the INTENDED state (like the Dell branch) -
    # do not derive success from the WMI return string alone. Lenovo CurrentSetting is
    # "SecureBoot,<value>[,...]"; the value token is element [1]. A refused commit that
    # still returned the STRING 'Success' would otherwise be reported as a clean success
    # while the setting silently reverts on the next boot.
    $newVal = ''
    if ($new) { $parts = "$new" -split ','; if ($parts.Count -ge 2) { $newVal = $parts[1].Trim() } }
    $err = ''
    if ("$setRes" -ne 'Success' -or "$saveRes" -ne 'Success') {
        $err = "Lenovo BIOS write failed (SetBiosSetting='$setRes', SaveBiosSettings='$saveRes'); check the supervisor BIOS password. Secure Boot NOT persisted."
    } elseif ($newVal -notmatch '^(?i)enable') {
        # WMI accepted the write but the read-back does not (yet) show SecureBoot enabled.
        # Lenovo applies the staged setting on the next boot - report pending, not a clean
        # success, so an un-applied/reverted setting is never counted as done.
        $new = "$new (pending reboot)"
    }
    New-Result -Mfr 'Lenovo' -Current $current -SetResult "set=$setRes; save=$saveRes" -New $new -Err $err
}

function Enable-HPSecureBoot {
    $ns          = 'root\HP\InstrumentedBIOS'
    $sbLabels    = @('Secure Boot', 'Configure Legacy Support and Secure Boot')
    $enabledVals = @('Enable', 'Legacy Support Disable and Secure Boot Enable')

    $current   = ((Get-WmiObject -Namespace $ns -Class HP_BIOSEnumeration -EA Stop |
                      Where-Object { $_.Name -in $sbLabels }) | Select-Object -First 1).CurrentValue

    # Idempotent re-run guard: the current value already reads as an enabled label yet
    # the OS-booted-state gate upstream did NOT short-circuit => the enable is already
    # STAGED and the host is PENDING REBOOT. Skip re-firing SetBIOSSetting and report
    # the already-pending state instead of re-writing the (already-set) value.
    if ("$current" -in $enabledVals) {
        return New-Result -Mfr 'HP' -Current $current -SetResult 'AlreadyPending' `
            -New "$current (already pending reboot)" -Err ''
    }

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

    # HP quirk: HP_BIOSEnumeration.CurrentValue reflects the currently BOOTED
    # setting, not staged NVRAM changes. After SetBIOSSetting returns 0 (success)
    # the change is queued for the next boot but the immediate read-back still
    # shows the old value. Treat a 0 return as authoritative and report the staged
    # target with a pending-reboot marker; any non-zero return falls back to the
    # raw read-back so real failures aren't masked.
    # HP return codes: 0=Success, 1=Not Supported, 2=Unspecified, 3=Timeout,
    # 4=Failed, 5=Invalid Param, 6=Access Denied (bad pwd).
    $postValue = ((Get-WmiObject -Namespace $ns -Class HP_BIOSEnumeration -EA Stop |
                      Where-Object { $_.Name -in $sbLabels }) | Select-Object -First 1).CurrentValue
    $err = ''
    if ($setRes -eq 0) {
        $new = "$targetVal (pending reboot)"
    } else {
        $new = $postValue
        $err = "HP SetBIOSSetting returned $setRes (1=NotSupported 4=Failed 5=InvalidParam 6=AccessDenied/bad password); Secure Boot NOT staged."
    }
    New-Result -Mfr 'HP' -Current $current -SetResult $setRes -New $new -Err $err
}

function Enable-DellSecureBoot {
    $ns      = 'root/dcim/sysman/biosattributes'
    $current = (Get-CimInstance -Namespace $ns -ClassName EnumerationAttribute -EA Stop |
                    Where-Object AttributeName -eq 'SecureBoot').CurrentValue

    # Idempotent re-run guard: the firmware-config current value ALREADY shows Secure
    # Boot enabled, yet the OS-booted-state gate upstream did NOT short-circuit
    # (Confirm-SecureBootUEFI still reports OFF) => the enable is already STAGED and the
    # host is PENDING REBOOT. Re-firing SetAttribute would needlessly re-write the
    # already-set value, so SKIP the write and report the already-pending state.
    if ("$current" -match '^(?i)\s*enabl') {
        return New-Result -Mfr 'Dell' -Current $current -SetResult 'AlreadyPending' `
            -New "$current (already pending reboot)" -Err ''
    }

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
        # Dell (like HP) exposes the currently-BOOTED value in EnumerationAttribute.CurrentValue,
        # not the staged NVRAM change. SetAttribute returned 0 (accepted) but the read-back is
        # unchanged => the setting is STAGED for the next boot, not applied now. Report a
        # pending-reboot state (mirroring the HP branch) instead of a clean immediate success.
        $new = "$new (pending reboot)"
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

# ----------------------------------------------------------------------------
# audit 2026-07-24 (P1): SUSPEND BITLOCKER BEFORE THE FIRMWARE WRITE.
# Turning Secure Boot on changes the boot-measurement PCRs the TPM seals the
# BitLocker volume master key to, so on the pending reboot a TPM-protected
# volume no longer unseals and the host stops at the 48-digit RECOVERY KEY
# prompt. Across a wave that strands every user who does not have their key -
# the highest-consequence failure this tool can cause. Suspending for exactly
# ONE reboot lets that boot proceed unsealed; protection auto-resumes after it
# and re-seals against the NEW (Secure Boot on) PCR values.
# Only TPM-BACKED protectors are PCR-sealed - a password/recovery-password-only
# volume is unaffected, so it is left alone rather than needlessly suspended.
# FAIL CLOSED: if a volume that needs suspending cannot be suspended (or its
# state cannot be read at all), the caller REFUSES the firmware write on this
# host. Writing blind is what strands a fleet; refusing only costs a re-run.
# ----------------------------------------------------------------------------
function Suspend-TpmBitLockerForFirmware {
    $res = [PSCustomObject]@{ Ok = $true; Detail = ''; Suspended = @() }

    # No BitLocker cmdlets => we cannot suspend anything, so the ONLY safe way past
    # this branch is POSITIVE proof that nothing is protected. Corroborate with
    # manage-bde when it exists.
    if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) -or
        -not (Get-Command Suspend-BitLocker  -ErrorAction SilentlyContinue)) {
        $mbde = Join-Path $env:SystemRoot 'System32\manage-bde.exe'
        if (-not (Test-Path -LiteralPath $mbde)) {
            # Neither the cmdlets NOR manage-bde exist: the BitLocker feature is genuinely
            # not installed on this box, so no volume can be TPM-sealed. That is a positive
            # fact about the host - not an unread state - so it may proceed.
            $res.Detail = 'BitLocker cmdlets and manage-bde are both absent (feature not installed); no volume can be TPM-sealed.'
            return $res
        }
        # audit 2026-07-25 (fable re-audit follow-up): this fallback FAILED OPEN. A throw,
        # a non-zero exit, empty output, or LOCALIZED output (the old regex matched only the
        # English 'Protection Status: Protection On') all fell through to Ok=$true with a
        # Detail asserting "no protected volume to suspend" when the true state was UNKNOWN -
        # and the firmware write then proceeded on a genuinely protected volume. Unknown is
        # now a REFUSAL, matching the fail-closed contract the rest of this function keeps.
        $st = ''; $exitBad = $false
        try {
            $st = (& $mbde -status 2>&1 | Out-String)
            # $LASTEXITCODE is only meaningful once a native command has actually set it; a
            # $null here means "no signal", NOT success - the parse gate below is what
            # decides, and it refuses anything it cannot positively read.
            if ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) { $exitBad = $true }
        } catch { $st = ''; $exitBad = $true }
        if ($exitBad -or [string]::IsNullOrWhiteSpace($st)) {
            $res.Ok = $false
            $res.Detail = 'BitLocker state could not be determined - refusing the firmware write (the BitLocker cmdlets are absent and manage-bde -status failed or returned no output).'
            return $res
        }
        # POSITIVE parse only. Every volume block must yield a readable 'Protection Status:'
        # line; if none parse, the output is localized/unexpected and we do not know what we
        # are looking at, so we refuse rather than assume "off".
        $stLines = @([regex]::Matches($st, '(?im)^\s*Protection\s+Status:\s*(.+?)\s*$'))
        if ($stLines.Count -eq 0) {
            $res.Ok = $false
            $res.Detail = 'BitLocker state could not be determined - refusing the firmware write (manage-bde -status produced no readable "Protection Status:" line; the output may be localized).'
            return $res
        }
        if (@($stLines | Where-Object { $_.Groups[1].Value -match '(?i)Protection\s+On' }).Count -gt 0) {
            $res.Ok = $false
            $res.Detail = 'BitLocker protection is ON but the BitLocker PowerShell cmdlets are unavailable, so it cannot be suspended for the reboot.'
            return $res
        }
        if (@($stLines | Where-Object { $_.Groups[1].Value -notmatch '(?i)Protection\s+Off' }).Count -gt 0) {
            $res.Ok = $false
            $res.Detail = 'BitLocker state could not be determined - refusing the firmware write (manage-bde -status reported a protection state this payload does not recognise).'
            return $res
        }
        $res.Detail = "BitLocker cmdlets not present; manage-bde reports every volume Protection Off ($($stLines.Count) volume(s)) - no protected volume to suspend."
        return $res
    }

    # TPM-backed protector types (the PCR-sealed ones).
    $tpmTypes = @('Tpm','TpmPin','TpmStartupKey','TpmPinStartupKey')
    $vols = @()
    try {
        $vols = @(Get-BitLockerVolume -ErrorAction Stop | Where-Object {
            ("$($_.ProtectionStatus)" -match '(?i)^(On|1)$') -and
            (@($_.KeyProtector | Where-Object { $tpmTypes -contains "$($_.KeyProtectorType)" }).Count -gt 0)
        })
    } catch {
        $res.Ok = $false
        $res.Detail = "Could not read BitLocker volume state ($($_.Exception.Message))."
        return $res
    }
    if ($vols.Count -eq 0) {
        $res.Detail = 'No TPM-sealed BitLocker volume; nothing to suspend.'
        return $res
    }

    $done = New-Object System.Collections.ArrayList
    foreach ($v in $vols) {
        $mp = "$($v.MountPoint)"
        try {
            Suspend-BitLocker -MountPoint $mp -RebootCount 1 -ErrorAction Stop | Out-Null
        } catch {
            $res.Ok = $false
            $res.Detail = "Suspend-BitLocker failed on $mp : $($_.Exception.Message)"
            return $res
        }
        # Verify the suspend actually took - a silent no-op would leave the volume
        # PCR-sealed and we would still strand the host.
        try {
            $after = Get-BitLockerVolume -MountPoint $mp -ErrorAction Stop
            if ("$($after.ProtectionStatus)" -match '(?i)^(On|1)$') {
                $res.Ok = $false
                $res.Detail = "Suspend-BitLocker on $mp returned without error but protection is still ON."
                return $res
            }
        } catch {
            $res.Ok = $false
            $res.Detail = "Could not verify the BitLocker suspend on $mp : $($_.Exception.Message)"
            return $res
        }
        [void]$done.Add($mp)
    }
    $res.Suspended = $done.ToArray()
    $res.Detail    = "Suspended for 1 reboot: $($done -join ', ')"
    return $res
}

# ----------------------------------------------------------------------------
# audit 2026-07-25 (fable re-audit follow-up): RESUME WHAT WE SUSPENDED FOR NOTHING.
# The suspend runs BEFORE the manufacturer switch, so an unsupported OEM or a
# rejected OEM write (wrong BIOS password, setting absent, commit refused) left the
# host with BitLocker suspended for its next reboot and ZERO firmware change to show
# for it - a needless unprotected boot. Resume protection on those paths.
# Deliberately NOT called when the write DID (or may have) happened: an already-
# staged 'AlreadyPending' host still faces a re-measured next boot, and after an
# unexpected exception the write state is unknown - resuming a host whose firmware
# did change is exactly what strands it at the recovery prompt. One unprotected boot
# is the safe side of that trade; a recovery-key prompt is not.
# ----------------------------------------------------------------------------
function Resume-TpmBitLockerAfterNoWrite {
    param($MountPoints)
    $res = [PSCustomObject]@{ Ok = $true; Detail = '' }
    $mps = @($MountPoints)
    if ($mps.Count -eq 0) { return $res }
    if (-not (Get-Command Resume-BitLocker -ErrorAction SilentlyContinue)) {
        $res.Ok = $false
        $res.Detail = "resume FAILED on $($mps -join ', ') (Resume-BitLocker unavailable) - protection stays suspended until the next reboot."
        return $res
    }
    $back = New-Object System.Collections.ArrayList
    $bad  = New-Object System.Collections.ArrayList
    foreach ($mp in $mps) {
        try {
            Resume-BitLocker -MountPoint $mp -ErrorAction Stop | Out-Null
            [void]$back.Add($mp)
        } catch {
            $res.Ok = $false
            [void]$bad.Add("$mp ($($_.Exception.Message))")
        }
    }
    # Report honestly per host: a partial resume must not read as a clean one.
    $parts = New-Object System.Collections.ArrayList
    if ($back.Count -gt 0) { [void]$parts.Add("no firmware change was made, so BitLocker was RESUMED on $($back -join ', ')") }
    if ($bad.Count  -gt 0) { [void]$parts.Add("resume FAILED on $($bad -join '; ') - protection stays suspended until the next reboot") }
    $res.Detail = ($parts -join '; ')
    return $res
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
    # Treat the "unknown" branch as a hard stop. Supported=$null (generic
    # Confirm-SecureBootUEFI failure: EFI driver missing, insufficient rights,
    # etc.) must NOT fall through to the OEM write path.
    elseif ($null -eq $osSB.Supported) {
        # UNREADABLE state (generic Confirm-SecureBootUEFI failure: EFI driver missing,
        # insufficient rights, etc.). This is NOT "already compliant" - it is indeterminate.
        # Flag it DISTINCTLY (Unknown=$true, SetResult='Unknown', Skipped=$false) so the
        # consumer resolves a distinct 'Unknown' status rather than bucketing it as
        # 'Skipped' alongside an already-enabled host. Still NO BIOS write is attempted.
        $out = [PSCustomObject]@{
            Manufacturer = $mfr
            CurrentValue = 'Unknown'
            SetResult    = 'Unknown'
            NewValue     = 'Unknown'
            Error        = 'Could not determine Secure Boot support state (Confirm-SecureBootUEFI failed). BIOS write not attempted.'
            Skipped      = $false
            Unknown      = $true
            Timestamp    = (Get-Date -Format 'o')
        }
    }
    else {
        # BRICK-SAFETY: Confirm-SecureBootUEFI not throwing means the OS booted
        # UEFI, but a UEFI-capable box can still be on a Legacy/CSM path or an MBR
        # system disk, where committing Secure Boot (especially Lenovo's persistent
        # Save) can leave it UNBOOTABLE. Positively verify UEFI firmware mode + a
        # GPT system/boot disk and SKIP anything we cannot confirm safe.
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
            # audit 2026-07-24 (P3): a brick-safety stop is a REFUSAL, not a success.
            # It used to ride out as SetResult/Skipped='Skipped'/$true, which the
            # consumer bucketed with "already enabled" and painted green - so a host
            # JANET deliberately declined to touch read as done. Refused=$true gives
            # it its own status + tally; Skipped stays $false so nothing conflates them.
            $out = [PSCustomObject]@{
                Manufacturer = $mfr
                CurrentValue = 'N/A'
                SetResult    = 'Refused'
                NewValue     = 'N/A'
                Error        = "Brick-safety stop: $bootWhy. Enabling Secure Boot on a non-UEFI/non-GPT boot path can make the host unbootable - resolve the boot mode first. No BIOS write attempted."
                Skipped      = $false
                Refused      = $true
                Timestamp    = (Get-Date -Format 'o')
            }
        }
        else {
            # audit 2026-07-24 (P1): suspend BitLocker for ONE reboot BEFORE the write.
            # A Secure Boot change re-measures the boot PCRs, so a TPM-sealed volume
            # would demand its recovery key on the pending reboot. Fail CLOSED - if the
            # suspend did not take, REFUSE this host instead of writing firmware that
            # could leave it unbootable for a user who has no recovery key.
            $bl = Suspend-TpmBitLockerForFirmware
            if (-not $bl.Ok) {
                $out = [PSCustomObject]@{
                    Manufacturer = $mfr
                    CurrentValue = 'N/A'
                    SetResult    = 'Refused'
                    NewValue     = 'N/A'
                    Error        = "BitLocker safety stop: $($bl.Detail) Enabling Secure Boot re-measures the boot PCRs the volume key is sealed to, so this host would stop at the BitLocker recovery-key prompt on the next boot. No BIOS write attempted."
                    Skipped      = $false
                    Refused      = $true
                    BitLocker    = "NOT SUSPENDED - $($bl.Detail)"
                    Timestamp    = (Get-Date -Format 'o')
                }
            }
            else {
                $out = switch -Regex ($mfr) {
                    'LENOVO'      { Enable-LenovoSecureBoot; break }
                    'HP|Hewlett'  { Enable-HPSecureBoot;     break }
                    'Dell'        { Enable-DellSecureBoot;   break }
                    default  {
                        New-Result -Mfr $mfr -Current 'N/A' -SetResult 'N/A' -New 'N/A' `
                            -Err "Unsupported manufacturer [$mfr] - no changes made."
                    }
                }
                if ($null -ne $out -and -not ($out | Get-Member -Name 'Skipped' -EA SilentlyContinue)) {
                    $out | Add-Member -NotePropertyName Skipped -NotePropertyValue $false
                }
                # audit 2026-07-25 (fable re-audit follow-up): NO firmware change happened on
                # this host - unsupported OEM, or the OEM branch reported the write rejected/
                # not staged/not persisted (every such branch sets a non-empty Error). The
                # one-reboot suspend therefore bought nothing and would only cost the user an
                # unprotected boot, so resume protection now. EXCEPTION: 'AlreadyPending' means
                # the enable is ALREADY staged and the next boot is the re-measured one - that
                # host genuinely needs the suspend, so leave it suspended.
                $blDetail = [string]$bl.Detail
                if ($null -ne $out -and @($bl.Suspended).Count -gt 0 -and
                    "$($out.SetResult)" -ne 'AlreadyPending' -and "$($out.Error)") {
                    $rb = Resume-TpmBitLockerAfterNoWrite -MountPoints $bl.Suspended
                    if ("$($rb.Detail)") { $blDetail = "$blDetail | $($rb.Detail)" }
                }
                # Report the suspension outcome per host, honestly, on the row itself -
                # the operator has to know whether this box will come back up clean.
                if ($null -ne $out) {
                    $out | Add-Member -NotePropertyName BitLocker -NotePropertyValue $blDetail -Force
                }
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

# SECURITY: this script file carries the BIOS password in plaintext. Self-delete
# it the instant the result is written so it does not linger on the target's disk
# (the launcher's finally + close-cleanup are backstops).
if ($PSCommandPath) { Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue }
'@

# ----------------------------------------------------------------------------
# Dry-run per-host worker: AFNET-safe TCP (5985/5986/445) reachability + WinRM
# manufacturer detection only. No firmware write, no scheduled task, no DCOM.
# A red dry-run predicts a live failure.
# ----------------------------------------------------------------------------
$script:SbeDryWorker = {
    param($comp, $cred)
    # Reachability over TCP - probe 5985 (WinRM HTTP) then 5986 (WinRM HTTPS) then
    # 445 (SMB) with a short connect budget, break on first connect (HTTP preferred
    # when both are open). NEVER ICMP (AFNET GPO blocks echo) and NEVER a DCOM/RPC
    # CIM session: where the host firewall exposes 5985/5986/445 but not the RPC range
    # (the stated AFNET posture) a DCOM probe reported reachable hosts 'unreachable'
    # and burned the full OperationTimeout per offline host. $useSsl is set ONLY
    # when the port that answered is 5986, so the WinRM call below auto-switches to
    # -UseSSL (SMB answering alone is a liveness signal, not a WinRM transport).
    $reachable = $false; $useSsl = $false
    foreach ($port in 5985,5986,445) {
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($comp, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) { $reachable = $true; if ($port -eq 5986) { $useSsl = $true } }
        } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
        if ($reachable) { break }
    }
    if (-not $reachable) {
        return [ordered]@{
            Computer     = $comp
            Status       = 'Error'
            Manufacturer = '?'
            Before       = 'N/A (Dry Run)'
            After        = 'N/A (Dry Run)'
            SetResult    = 'N/A (Dry Run)'
            BitLocker    = 'N/A (Dry Run)'
            Error        = 'Unreachable: no TCP on 5985/5986 (WinRM) or 445 (SMB) within 1.5s.'
            Skipped      = $false
        }
    }
    # Manufacturer over WinRM: Get-CimInstance runs LOCALLY on the target inside
    # Invoke-Command (no DCOM CIM session). Mirror the suite splat - Negotiate
    # always, Credential only when the operator supplied one. -UseSSL only when the
    # host answered ONLY on 5986 (self-signed WinRM HTTPS is common on AFNET, so
    # skip CA/CN validation - the transport stays encrypted; port 5986 is implicit).
    try {
        $soP = @{ OperationTimeout=20000; OpenTimeout=15000; CancelTimeout=5000; IdleTimeout=60000 }
        if ($useSsl) { $soP['SkipCACheck']=$true; $soP['SkipCNCheck']=$true }
        $wsOpt  = New-PSSessionOption @soP
        $icArgs = @{
            ComputerName   = $comp
            Authentication = 'Negotiate'
            SessionOption  = $wsOpt
            ErrorAction    = 'Stop'
            ScriptBlock    = { (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).Manufacturer }
        }
        if ($useSsl) { $icArgs['UseSSL'] = $true }
        if ($cred) { $icArgs['Credential'] = $cred }
        $mfr = Invoke-Command @icArgs
        return [ordered]@{
            Computer     = $comp
            Status       = 'DryRun'
            Manufacturer = "$mfr"
            Before       = 'N/A (Dry Run)'
            After        = 'N/A (Dry Run)'
            SetResult    = 'N/A (Dry Run)'
            BitLocker    = 'N/A (Dry Run)'
            Error        = ''
            Skipped      = $false
        }
    } catch {
        return [ordered]@{
            Computer     = $comp
            Status       = 'Error'
            Manufacturer = '?'
            Before       = 'N/A (Dry Run)'
            After        = 'N/A (Dry Run)'
            SetResult    = 'N/A (Dry Run)'
            BitLocker    = 'N/A (Dry Run)'
            Error        = "WinRM unreachable (TCP open but WinRM/5985/5986 did not answer): $($_.Exception.Message)"
            Skipped      = $false
        }
    }
}

# ----------------------------------------------------------------------------
# Live per-host worker: drop password-bearing payload .ps1 to C$ (SYSTEM+Admins
# ACL) over SMB, register + start a SYSTEM scheduled task over a WinRM session
# (ScheduledTasks cmdlets run LOCALLY on the target - no DCOM), poll the
# result JSON off the share (90s deadline + final read), then clean up the task
# and temp files. $biosPlain is the already-validated plaintext (forbidden chars
# rejected upstream); single-quote-escaping for the baked literal is preserved.
# ----------------------------------------------------------------------------
$script:SbeLiveWorker = {
    param($comp, $biosPlain, $payloadScript, $cred, $taskName)

    # loop57: name the result file with the per-run-unique $taskName (SBE_<random>), not the
    # hostname alone. A prior run's result file (same host, different taskName) then can never
    # share THIS run's filename, so the poll cannot replay a stale SetResult=0 JSON as this run's
    # Success if a pre-run cleanup ever silently failed. Mirrors $scriptFile = "$taskName.ps1".
    $resultFile = "SecureBoot_${comp}_${taskName}.json"
    $remotePath = "C:\Windows\Temp\$resultFile"
    # C$ is an admin share; the $ literal must be escaped inside the double-quoted
    # expansion so PS doesn't try to interpolate "$\Windows".
    $uncPath    = "\\$comp\C`$\Windows\Temp\$resultFile"
    $scriptFile      = "$taskName.ps1"
    $localScriptPath = "C:\Windows\Temp\$scriptFile"
    $scriptUnc       = "\\$comp\C`$\Windows\Temp\$scriptFile"

    # SECURITY: escape single quotes in BOTH values baked into single-quoted PS
    # literals - the password AND $remotePath (which embeds the operator-supplied
    # hostname). Hostnames are also allow-list validated upstream, so this is
    # defense-in-depth. Single-quoted PS strings are literal (no backtick / $
    # interpretation) so doubling ' suffices.
    $escPwd     = $biosPlain -replace "'", "''"
    $escPath    = $remotePath -replace "'", "''"
    $fullScript = "`$BIOSPassword = '$escPwd'`n" +
                  "`$ResultPath   = '$escPath'`n" +
                  $payloadScript
    $escPwd     = $null

    $session   = $null
    $taskOwned = $false        # true once Register succeeds
    $result    = $null
    $earlyErr  = $null
    $fileSeen  = $false        # result file ever observed on the share
    $lastParseErr = $null
    $sbDrive        = "SBE_$($comp -replace '[^A-Za-z0-9]','')"
    $sbDriveMounted = $false
    # audit 2026-07-24 (P3): the post-run "was C$ even reachable?" diagnosis used to
    # probe the share AFTER the finally had removed the credentialed PSDrive, so the
    # probe ran on the SERVER's own token and a host that had simply timed out came
    # back "permission denied". Sample it while the $cred SMB session is still up.
    $shareReachable = $null
    try {
        # AFNET-safe: open ONE WinRM session up front (Register here, Start next,
        # Unregister in finally) instead of a DCOM CIM session. Opened FIRST, before
        # any C$/SMB is touched, so the wrong-box guard right below can hard-abort
        # BEFORE the password-bearing payload is ever dropped onto the target.
        # Mirror the suite splat - Authentication=Negotiate always, Credential only
        # when supplied. IdleTimeout exceeds the 90s poll so the session is still
        # alive for the finally Unregister.
        # Transport probe (TCP, non-throwing): dial this session over HTTPS when the box
        # answers ONLY on WinRM 5986 (not 5985). The SCAN's READY-TO-ENABLE verdict + Dry Run
        # were widened to 5986, so the live enable MUST follow the same transport or a
        # 5986-only host green-lights then fails at New-PSSession. 5985 preferred when both open.
        $useSsl = $false
        foreach ($p in 5985,5986) {
            $tc = $null
            try {
                $tc = New-Object System.Net.Sockets.TcpClient
                $iar = $tc.BeginConnect($comp, $p, $null, $null)
                if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) { if ($p -eq 5986) { $useSsl = $true }; break }
            } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
        }
        $soArgs = @{ OperationTimeout=60000; OpenTimeout=15000; CancelTimeout=5000; IdleTimeout=300000 }
        if ($useSsl) { $soArgs['SkipCACheck']=$true; $soArgs['SkipCNCheck']=$true }
        $wsOpt    = New-PSSessionOption @soArgs
        $sessArgs = @{ ComputerName=$comp; Authentication='Negotiate'; SessionOption=$wsOpt; ErrorAction='Stop' }
        if ($useSsl) { $sessArgs['UseSSL'] = $true }
        if ($cred) { $sessArgs['Credential'] = $cred }
        $session = New-PSSession @sessArgs

        # Wrong-box guard (P2-6b, HARD ABORT): the box that answers this WinRM
        # session may not be the one we dialed (stale DNS / reused IP). Verify
        # BEFORE dropping the password-bearing payload or arming the Secure Boot
        # task. IP-literal targets have no DNS indirection (the box answering at
        # that IP IS the box), so skip the compare for them.
        $expectedName = if ($comp -match '^\d{1,3}(\.\d{1,3}){3}$') { '' } else { ($comp -split '\.')[0] }
        if ($expectedName) {
            $answeringName = Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock { $env:COMPUTERNAME }
            if ($answeringName.Trim().ToUpper() -ne $expectedName.Trim().ToUpper()) {
                throw "wrong box: dialed '$expectedName', answered '$answeringName' - ABORTED, Secure Boot task not armed"
            }
        }

        # CREDENTIAL: mount the target C$ admin share with the operator credential
        # so the payload drop, ACL lock, result read-back and cleanup all
        # authenticate as $cred - NOT the server process token. Once this SMB
        # session is established, other UNC access to \\$comp on this logon session
        # (including the native icacls call below) reuses it. With no credential,
        # fall back to the server identity (prior behaviour). Mirrors the
        # pkginstall worker's "mount C$ with credential" pattern.
        if (Get-PSDrive -Name $sbDrive -ErrorAction SilentlyContinue) {
            Remove-PSDrive -Name $sbDrive -Force -ErrorAction SilentlyContinue
        }
        if ($cred) {
            New-PSDrive -Name $sbDrive -PSProvider FileSystem -Root "\\$comp\C`$" -Credential $cred -ErrorAction Stop | Out-Null
        } else {
            New-PSDrive -Name $sbDrive -PSProvider FileSystem -Root "\\$comp\C`$" -ErrorAction Stop | Out-Null
        }
        $sbDriveMounted = $true

        # Clean any stale result file from a previous run (now over the $cred session).
        Remove-Item -LiteralPath $uncPath -Force -ErrorAction SilentlyContinue

        # SECURITY: drop the password-bearing payload to a file on the target,
        # lock it to SYSTEM + Administrators (well-known SIDs, best-effort), and
        # run it with -File - NOT in the task command line.
        Set-Content -LiteralPath $scriptUnc -Value $fullScript -Encoding UTF8 -Force -ErrorAction Stop
        $fullScript = $null
        & icacls.exe "$scriptUnc" /inheritance:r /grant:r "*S-1-5-18:(M)" "*S-1-5-32-544:(M)" 2>$null | Out-Null

        Invoke-Command -Session $session -ArgumentList $taskName, $localScriptPath -ErrorAction Stop -ScriptBlock {
            param($tn, $scriptPath)
            $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
                          -Argument "-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
            $princ  = New-ScheduledTaskPrincipal -UserId 'SYSTEM' `
                          -RunLevel Highest -LogonType ServiceAccount
            $stSet  = New-ScheduledTaskSettingsSet `
                          -ExecutionTimeLimit (New-TimeSpan -Minutes 5) `
                          -MultipleInstances IgnoreNew
            Register-ScheduledTask -TaskName $tn -Action $action `
                -Principal $princ -Settings $stSet -Force -ErrorAction Stop | Out-Null
        }
        $taskOwned = $true
        Invoke-Command -Session $session -ArgumentList $taskName -ErrorAction Stop -ScriptBlock {
            param($tn)
            Start-ScheduledTask -TaskName $tn -ErrorAction Stop
        }

        # Poll for the result JSON. 90s deadline, 4s interval. Read whenever the
        # file exists and accept only a parse that has the expected fields, so a
        # half-written file is retried rather than accepted as a fieldless object.
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
        # One final read after the deadline: the payload may have finished writing
        # in the last interval. Without this a host that succeeded ~now is reported
        # Timeout and the operator re-runs an enable that actually worked.
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
        # Cleanup MUST run even if Register/Start threw: unregister the task, drop
        # the WinRM session, and remove BOTH the result file and the password-bearing
        # script file from the target.
        $fullScript = $null
        if ($taskOwned) {
            # Prefer the original WinRM session. But if it dropped during the 90s
            # SMB result-poll ($session.State no longer 'Opened'), Unregister over it
            # silently no-ops and the completed ONCE task is orphaned on the target.
            # In that case open a short-lived session on the SAME auth/cred path the
            # worker used, purely to Unregister by unique task name.
            $sessionUsable = $false
            if ($session) {
                try { $sessionUsable = ("$($session.State)" -eq 'Opened') } catch { $sessionUsable = $false }
            }
            if ($sessionUsable) {
                Invoke-Command -Session $session -ArgumentList $taskName -ErrorAction SilentlyContinue -ScriptBlock {
                    param($tn) Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue
                }
            } else {
                try {
                    $cuSoArgs = @{ OperationTimeout=60000; OpenTimeout=15000; CancelTimeout=5000 }
                    if ($useSsl) { $cuSoArgs['SkipCACheck']=$true; $cuSoArgs['SkipCNCheck']=$true }
                    $cuOpt  = New-PSSessionOption @cuSoArgs
                    $cuArgs = @{ ComputerName=$comp; Authentication='Negotiate'; SessionOption=$cuOpt; ErrorAction='Stop' }
                    if ($useSsl) { $cuArgs['UseSSL'] = $true }
                    if ($cred) { $cuArgs['Credential'] = $cred }
                    $cleanupSess = New-PSSession @cuArgs
                    try {
                        Invoke-Command -Session $cleanupSess -ArgumentList $taskName -ErrorAction SilentlyContinue -ScriptBlock {
                            param($tn) Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue
                        }
                    } finally {
                        Remove-PSSession $cleanupSess -ErrorAction SilentlyContinue
                    }
                } catch {
                    # Host unreachable now (WinRM down / offline): nothing more we can
                    # do - fall back silently rather than fail the whole run.
                    $null = $_
                }
            }
        }
        if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
        Remove-Item -LiteralPath $uncPath   -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $scriptUnc -Force -ErrorAction SilentlyContinue
        if ($sbDriveMounted) {
            # audit 2026-07-24 (P3): sample C$ reachability BEFORE dropping the drive -
            # once the credentialed SMB session is gone the same probe authenticates as
            # the server process and mislabels a timeout as "permission denied".
            if ($null -eq $result) {
                try { $shareReachable = [bool](Test-Path -LiteralPath "\\$comp\C`$\Windows\Temp" -ErrorAction SilentlyContinue) } catch { $shareReachable = $false }
            }
            Remove-PSDrive -Name $sbDrive -Force -ErrorAction SilentlyContinue
        }
    }

    if ($earlyErr) {
        return [ordered]@{
            Computer=$comp; Status='Error'; Manufacturer='?'
            Before='?'; After='?'; SetResult='?'; BitLocker='n/a'; Error=$earlyErr; Skipped=$false
        }
    }
    if ($null -eq $result) {
        # Distinguish corrupt-but-present, C$ not accessible, and a genuine no-show.
        if ($fileSeen) {
            $msg = if ($lastParseErr) { "Result file was present but unreadable/corrupt: $lastParseErr" }
                   else { 'Result file present but missing expected fields (payload may have crashed mid-write).' }
            return [ordered]@{ Computer=$comp; Status='Error'; Manufacturer='?'; Before='?'; After='?'; SetResult='?'; BitLocker='n/a'; Error=$msg; Skipped=$false }
        }
        # audit 2026-07-24 (P3): use the reading taken while the credentialed PSDrive was
        # STILL mounted (see $shareReachable above). Only fall back to a live probe if the
        # drive never got mounted at all - otherwise this call would run on the server's
        # own token and report "denied" for what was really a timeout.
        $shareOk = if ($null -ne $shareReachable) { [bool]$shareReachable }
                   else { [bool](Test-Path -LiteralPath "\\$comp\C`$\Windows\Temp" -ErrorAction SilentlyContinue) }
        if (-not $shareOk) {
            return [ordered]@{ Computer=$comp; Status='Error'; Manufacturer='?'; Before='?'; After='?'; SetResult='?'; BitLocker='n/a'; Error="C`$ admin share not accessible on $comp with the run credential (permission denied or unreachable); the task may have run but the result could not be read."; Skipped=$false }
        }
        return [ordered]@{ Computer=$comp; Status='Timeout'; Manufacturer='?'; Before='?'; After='?'; SetResult='?'; BitLocker='n/a'; Error='Payload ran but produced no result within 90 s.'; Skipped=$false }
    }
    # loop59 (item62): 'AlreadyPending' means the host was ALREADY staged pending-reboot on a
    # prior run and this run wrote NOTHING (the vendor branch returns before re-firing the set/
    # save). It must resolve to 'Skipped' - not 'Success' - so a re-run doesn't book a fresh
    # VulnPatched/Success/itemCount=1 audit + inflate the "N enabled" count for work it didn't do.
    # audit 2026-07-24 (P3): 'Refused' is a SAFETY REFUSAL (brick-safety stop or a
    # BitLocker suspend that would not take) - JANET declined to write firmware and
    # nothing changed. It is neither a success nor an "already enabled" skip, so it
    # gets its own status and its own bucket upstream instead of being painted green.
    $resolvedStatus = if     ($result.Unknown -eq $true)             { 'Unknown' }
                      elseif ($result.Refused -eq $true)             { 'Refused' }
                      elseif ($result.Skipped -eq $true)             { 'Skipped' }
                      elseif ($result.SetResult -eq 'AlreadyPending'){ 'Skipped' }
                      elseif ($result.Error)                         { 'Error'   }
                      else                                           { 'Success' }
    return [ordered]@{
        Computer     = $comp
        Status       = $resolvedStatus
        Manufacturer = $result.Manufacturer
        Before       = $result.CurrentValue
        After        = $result.NewValue
        SetResult    = $result.SetResult
        BitLocker    = [string]$result.BitLocker   # audit 2026-07-24: per-host suspend outcome
        Error        = $result.Error
        Skipped      = [bool]($resolvedStatus -eq 'Skipped')   # align field to status (AlreadyPending now Skipped)
    }
}

# ----------------------------------------------------------------------------
# SCAN (v1.6.0) - read-only fleet Secure Boot posture. Mirrors the c2c 'scan'
# shape (plain WinRM Invoke-Command, TCP 5985/5986/445 pre-check, DNS-mismatch soft
# skip, per-host watchdog) - NONE of the C$-payload/scheduled-task machinery
# that the firmware WRITE needs. No 50-host cap, no admin-session gate.
# ----------------------------------------------------------------------------

# Admin-side verdict derivation (pure, deterministic, unit-testable). Runs in
# module scope (NOT in the pool worker), fed the raw fields the probe returns.
#   SecureBoot   : 'On' / 'Off' / 'NotUEFI/Unsupported' / 'Unknown'
#   Firmware     : 'UEFI' / 'Legacy' / 'Unknown'
#   Disk         : 'GPT' / 'MBR' / 'Unknown'
#   Manufacturer : Win32_ComputerSystem.Manufacturer
# Returns exactly one of: ENABLED / READY TO ENABLE / OFF - UNSUPPORTED OEM /
# BLOCKED - LEGACY/MBR / CHECK ERROR. (OFFLINE / DNS MISMATCH are host-level
# statuses resolved before this is ever called.)
function Get-SbeScanVerdict {
    param([string]$SecureBoot, [string]$Firmware, [string]$Disk, [string]$Manufacturer)
    $sb = ([string]$SecureBoot).Trim()
    $fw = ([string]$Firmware).Trim()
    $dk = ([string]$Disk).Trim()

    # Already compliant - nothing to do.
    if ($sb -match '^(?i)on$') { return 'ENABLED' }

    # Non-UEFI firmware or an MBR system disk cannot take Secure Boot safely; the
    # enabler must NOT be fed these (needs MBR2GPT / reimage first).
    if ($sb -match '^(?i)NotUEFI' -or $fw -match '^(?i)Legacy' -or $dk -match '^(?i)MBR') {
        return 'BLOCKED - LEGACY/MBR'
    }

    # An indeterminate Secure Boot state (Confirm-SecureBootUEFI unreadable and no
    # corroborating registry value) is NOT a clean 'Off' - never call it ready.
    if ($sb -notmatch '^(?i)off$') { return 'CHECK ERROR' }

    # Off, but we could not positively confirm the safe UEFI + GPT boot path.
    if ($fw -notmatch '^(?i)UEFI' -or $dk -notmatch '^(?i)GPT') { return 'CHECK ERROR' }

    # Off + UEFI + GPT: supported OEM (the enable payload's Dell/HP/Lenovo branches)
    # is ready to enable; any other manufacturer is a manual/desk-side job.
    if ($Manufacturer -match '(?i)LENOVO|HP|Hewlett|Dell') { return 'READY TO ENABLE' }
    return 'OFF - UNSUPPORTED OEM'
}

# Per-host read-only probe (runs in a pool runspace; no module scope here). One
# Invoke-Command round-trip; returns the raw fields + a host-level status. The
# verdict is computed admin-side (Get-SbeScanVerdict) by the orchestrator.
$script:SbeScanWorker = {
    param([string]$Computer, $Cred, [string]$Auth, [bool]$AttemptOffline)

    $r = [ordered]@{
        Computer=$Computer; Ping=''; HostStatus=''; SecureBoot='?'; Firmware='?';
        Disk='?'; Manufacturer='?'; Model='?'; Bios='?'; BiosDate=''; OsBuild='?'; Detail=''
    }

    # TCP reachability (WinRM HTTP 5985, then WinRM HTTPS 5986, then SMB 445, 1.5s;
    # break on first connect so HTTP wins when both are open). NEVER ICMP (AFNET
    # GPO). $useSsl is set ONLY when the port that answered is 5986, so the session
    # below auto-switches to -UseSSL (SMB answering alone is a liveness signal, not
    # a WinRM transport).
    $reachable = $false; $useSsl = $false
    foreach ($port in 5985,5986,445) {
        $tc = $null
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Computer, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) { $reachable = $true; $r.Ping = "TCP $port"; if ($port -eq 5986) { $useSsl = $true } }
        } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
        if ($reachable) { break }
    }
    if (-not $reachable) {
        $r.Ping = 'Unreachable'
        if (-not $AttemptOffline) { $r.HostStatus = 'OFFLINE'; $r.Detail = 'No TCP on 5985/5986/445 (1.5s timeouts). Enable "Attempt even if offline" to force.'; return $r }
    }

    # -UseSSL only when the host answered ONLY on 5986 (self-signed WinRM HTTPS is
    # common on AFNET, so skip CA/CN validation - the transport stays encrypted;
    # port 5986 is implicit).
    $soP = @{ OperationTimeout=90000; OpenTimeout=15000; CancelTimeout=5000; IdleTimeout=60000 }
    if ($useSsl) { $soP['SkipCACheck']=$true; $soP['SkipCNCheck']=$true }
    $wsOpt = New-PSSessionOption @soP
    $splat = @{ ComputerName=$Computer; SessionOption=$wsOpt; ErrorAction='Stop' }
    if ($useSsl) { $splat['UseSSL']=$true }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$Auth }
    $sess = $null
    try { $sess = New-PSSession @splat } catch { $r.HostStatus = 'CHECK ERROR'; $r.Detail = "Session: $($_.Exception.Message)"; return $r }

    $probeSb = {
        # 1. Secure Boot state: Confirm-SecureBootUEFI, then corroborate via the
        #    SecureBoot State registry key when the cmdlet is unavailable/unreadable.
        $sb = 'Unknown'
        try {
            $val = Confirm-SecureBootUEFI -ErrorAction Stop
            $sb = if ($val) { 'On' } else { 'Off' }
        } catch [System.PlatformNotSupportedException] {
            $sb = 'NotUEFI/Unsupported'
        } catch {
            try {
                $reg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name 'UEFISecureBootEnabled' -ErrorAction Stop
                $sb = if ([int]$reg.UEFISecureBootEnabled -eq 1) { 'On' } else { 'Off' }
            } catch { $sb = 'Unknown' }
        }

        # 2. Firmware type: $env:firmware_type (reliable on booted Windows), with a
        #    fallback: the SecureBoot State registry key only exists on UEFI firmware.
        $fw = 'Unknown'
        if ($env:firmware_type) {
            if     ($env:firmware_type -match '(?i)UEFI')        { $fw = 'UEFI' }
            elseif ($env:firmware_type -match '(?i)Legacy|BIOS') { $fw = 'Legacy' }
            else                                                 { $fw = [string]$env:firmware_type }
        }
        if ($fw -eq 'Unknown' -and (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State')) { $fw = 'UEFI' }

        # 3. System disk partition style (the disk holding C:).
        $disk = 'Unknown'
        try {
            if (Get-Command Get-Partition -ErrorAction SilentlyContinue) {
                $d = Get-Partition -DriveLetter 'C' -ErrorAction Stop | Get-Disk -ErrorAction Stop
                if ($d -and $d.PartitionStyle) { $disk = [string]$d.PartitionStyle }
            }
        } catch { $disk = 'Unknown' }
        if ([string]::IsNullOrWhiteSpace($disk) -or $disk -eq 'Unknown') {
            try {
                $bp = Get-CimInstance -ClassName Win32_DiskPartition -ErrorAction Stop | Where-Object { $_.BootPartition } | Select-Object -First 1
                if ($bp -and $bp.Type) { $disk = if ($bp.Type -match '(?i)GPT') { 'GPT' } else { 'MBR' } }
            } catch {}
        }
        if ([string]::IsNullOrWhiteSpace($disk)) { $disk = 'Unknown' }

        $cs = $null; $bios = $null; $os = $null
        try { $cs   = Get-CimInstance -ClassName Win32_ComputerSystem  -ErrorAction Stop } catch {}
        try { $bios = Get-CimInstance -ClassName Win32_BIOS            -ErrorAction Stop } catch {}
        try { $os   = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop } catch {}

        $biosDate = ''
        if ($bios -and $bios.ReleaseDate) { try { $biosDate = ([datetime]$bios.ReleaseDate).ToString('yyyy-MM-dd') } catch { $biosDate = [string]$bios.ReleaseDate } }

        [pscustomobject]@{
            RemoteName   = $env:COMPUTERNAME
            SecureBoot   = $sb
            Firmware     = $fw
            Disk         = $disk
            Manufacturer = if ($cs)   { [string]$cs.Manufacturer }     else { '?' }
            Model        = if ($cs)   { [string]$cs.Model }            else { '?' }
            Bios         = if ($bios) { [string]$bios.SMBIOSBIOSVersion } else { '?' }
            BiosDate     = $biosDate
            OsBuild      = if ($os)   { [string]$os.BuildNumber }      else { '?' }
        }
    }

    try {
        $p = Invoke-Command -Session $sess -ScriptBlock $probeSb -ErrorAction Stop
    } catch {
        $r.HostStatus = 'CHECK ERROR'; $r.Detail = "Probe: $($_.Exception.Message)"
        Remove-PSSession $sess -ErrorAction SilentlyContinue
        return $r
    } finally { if ($sess) { Remove-PSSession $sess -ErrorAction SilentlyContinue } }

    # DNS-mismatch soft-skip (read-only, name compare, never a PTR lookup). An
    # IP-literal target has no DNS indirection, so the guard is skipped for it.
    $actualName  = ([string]$p.RemoteName).Trim()
    $targetShort = ($Computer -split '\.')[0]
    $isIpLiteral = ($Computer -match '^\d{1,3}(\.\d{1,3}){3}$')
    if (-not $isIpLiteral -and $actualName -and ($actualName.ToUpper() -ne $targetShort.ToUpper())) {
        $r.HostStatus = 'DNS MISMATCH'; $r.Detail = "dialed '$targetShort' but remote is '$actualName' - skipped (would report the wrong machine)"
        return $r
    }

    $r.HostStatus   = 'OK'
    $r.SecureBoot   = [string]$p.SecureBoot
    $r.Firmware     = [string]$p.Firmware
    $r.Disk         = [string]$p.Disk
    $r.Manufacturer = [string]$p.Manufacturer
    $r.Model        = [string]$p.Model
    $r.Bios         = [string]$p.Bios
    $r.BiosDate     = [string]$p.BiosDate
    $r.OsBuild      = [string]$p.OsBuild
    return $r
}

# --- Action: scan-secure-boot (read-only) -----------------------------------
function Invoke-SbeScanAction {
    param([hashtable]$Params, [System.Management.Automation.PSCredential]$Credential, [scriptblock]$Emit)
    $send = { param($e) if ($Emit) { & $Emit $e } }

    $cancelJob = $null
    if ($Params -and $Params.ContainsKey('__job')) { $cancelJob = $Params['__job'] }
    $cancelCheck = { if ($cancelJob) { try { [bool]$cancelJob['Cancel'] } catch { $false } } else { $false } }.GetNewClosure()

    # No 50-host cap on the read-only scan (allow big pastes). Same clean host-list
    # parse the enable path uses (bare host/IPv4 tokens only).
    $targets = ConvertTo-SecureBootHostList ([string]$Params['targets'])
    if ($targets.Count -eq 0) {
        & $send @{ type='log'; level='warn'; text='No valid targets.' }
        return @{ rows=@(); summary=@{ total=0 } }
    }

    # Read-only: NO self-guard drop (scanning the dispatcher is harmless) and no
    # admin-session gate - mirrors the c2c scan conventions.
    $attemptOffline = Get-SbeBool $Params['attemptOffline'] $false
    $threads = 16
    if ($Params['threads']) { [int]::TryParse([string]$Params['threads'], [ref]$threads) | Out-Null }
    $threads = [Math]::Max(1, [Math]::Min(32, $threads))
    $perHostTimeout = 120
    $auth = if ($Credential) { 'Negotiate' } else { 'Default' }
    $authLabel = if ($Credential) { "as $($Credential.UserName)" } else { 'current session' }

    & $send @{ type='status'; text="Secure Boot fleet scan on $($targets.Count) host(s) with $threads thread(s)..." }
    & $send @{ type='log'; level='info'; text="[$(Get-Date -Format 'HH:mm:ss')] START Secure Boot scan on $($targets.Count) host(s) ($authLabel), $threads thread(s)." }

    $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $threads, $iss, $Host)
    $pool.Open()
    # Seed Queued rows so the operator sees the whole target list immediately.
    foreach ($h in $targets) { & $send (@{ type='row' } + @{ Host=$h; Ping=''; Verdict='Queued'; SecureBoot=''; Firmware=''; Disk=''; Manufacturer=''; Model=''; Detail='waiting for a runspace...' }) }
    $jobs = New-Object System.Collections.ArrayList
    foreach ($h in $targets) {
        $ps = [powershell]::Create(); $ps.RunspacePool = $pool
        [void]$ps.AddScript($script:SbeScanWorker)
        [void]$ps.AddArgument($h); [void]$ps.AddArgument($Credential); [void]$ps.AddArgument($auth); [void]$ps.AddArgument($attemptOffline)
        [void]$jobs.Add([pscustomobject]@{ Host=$h; PS=$ps; Async=$ps.BeginInvoke(); StartedAt=$null })
    }

    $rows       = New-Object System.Collections.ArrayList
    $readyHosts = New-Object System.Collections.ArrayList

    $emitResult = {
        param($res)
        $hostStatus = [string]$res.HostStatus
        if ($hostStatus -eq 'OK') {
            $verdict = Get-SbeScanVerdict -SecureBoot ([string]$res.SecureBoot) -Firmware ([string]$res.Firmware) -Disk ([string]$res.Disk) -Manufacturer ([string]$res.Manufacturer)
        } else {
            $verdict = $hostStatus   # OFFLINE / DNS MISMATCH / CHECK ERROR / Cancelled
        }
        $detail = [string]$res.Detail
        if ($hostStatus -eq 'OK') {
            $parts = New-Object System.Collections.ArrayList
            switch ($verdict) {
                'READY TO ENABLE'       { [void]$parts.Add('off + UEFI + GPT + supported OEM - safe to feed to Enable') }
                'ENABLED'               { [void]$parts.Add('Secure Boot already on - nothing to do') }
                'OFF - UNSUPPORTED OEM' { [void]$parts.Add("manufacturer '$($res.Manufacturer)' not supported by the enabler - manual/desk-side") }
                'BLOCKED - LEGACY/MBR'  { [void]$parts.Add('Legacy BIOS or MBR disk - run MBR2GPT / reimage before enabling') }
                'CHECK ERROR'           { [void]$parts.Add('could not positively confirm the UEFI + GPT boot path / Secure Boot state') }
            }
            if ($res.Bios -and $res.Bios -ne '?') { [void]$parts.Add("BIOS $($res.Bios)$(if ($res.BiosDate) { " ($($res.BiosDate))" } else { '' })") }
            if ($res.OsBuild -and $res.OsBuild -ne '?') { [void]$parts.Add("OS build $($res.OsBuild)") }
            $detail = ($parts -join '; ')
        }
        # informative-failures (loop80): a host-level CHECK ERROR carries the raw probe/session/DNS
        # error in $detail; turn it into a why+how-to-fix hint on this read-only scan path. OFFLINE and
        # DNS MISMATCH already carry a complete actionable detail, so scope the hint to CHECK ERROR.
        $hint = if ($verdict -eq 'CHECK ERROR' -and $hostStatus -ne 'OK' -and $detail) { Get-JanetTroubleshootHint -Message $detail -Server ([string]$res.Computer) } else { '' }
        $row = @{
            Host=[string]$res.Computer; Ping=[string]$res.Ping; Verdict=$verdict
            SecureBoot=[string]$res.SecureBoot; Firmware=[string]$res.Firmware; Disk=[string]$res.Disk
            Manufacturer=[string]$res.Manufacturer; Model=[string]$res.Model; Detail=$detail; Hint=[string]$hint
        }
        [void]$rows.Add($row)
        if ($verdict -eq 'READY TO ENABLE') { [void]$readyHosts.Add((([string]$res.Computer) -split '\.')[0]) }
        & $send (@{ type='row' } + $row)
        $lvl = switch ($verdict) {
            'READY TO ENABLE'       { 'ok' }
            'ENABLED'               { 'ok' }
            'CHECK ERROR'           { 'error' }
            'OFFLINE'               { 'warn' }
            'DNS MISMATCH'          { 'warn' }
            'BLOCKED - LEGACY/MBR'  { 'warn' }
            'OFF - UNSUPPORTED OEM' { 'warn' }
            default                 { 'info' }
        }
        & $send @{ type='log'; level=$lvl; text=("{0}: {1} - SB={2} FW={3} Disk={4} [{5} {6}]" -f $res.Computer, $verdict, $res.SecureBoot, $res.Firmware, $res.Disk, $res.Manufacturer, $res.Model) }
        if ($hint) { & $send @{ type='log'; level='err'; text="$([string]$res.Computer) : $verdict - $detail | FIX: $hint" } }
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
                    catch { $res = [ordered]@{ Computer=$j.Host; Ping=''; HostStatus='CHECK ERROR'; SecureBoot='?'; Firmware='?'; Disk='?'; Manufacturer='?'; Model='?'; Bios='?'; BiosDate=''; OsBuild='?'; Detail="worker error: $($_.Exception.Message)" } }
                    try { $j.PS.Dispose() } catch {}; $j.PS = $null
                    if ($null -eq $res) { $res = [ordered]@{ Computer=$j.Host; Ping=''; HostStatus='CHECK ERROR'; SecureBoot='?'; Firmware='?'; Disk='?'; Manufacturer='?'; Model='?'; Bios='?'; BiosDate=''; OsBuild='?'; Detail='worker returned no result' } }
                    & $emitResult $res
                    $done++; & $send @{ type='progress'; done=$done; total=$jobs.Count }
                }
            }
            # Per-host watchdog: abandon a host that overran its own clock (wedged read).
            if ($done -lt $jobs.Count) {
                $nowPh = Get-Date
                foreach ($j in $jobs) {
                    if ($j.PS -and $j.StartedAt -and ($nowPh - $j.StartedAt).TotalSeconds -gt $perHostTimeout) {
                        try { [void]$j.PS.BeginStop($null, $null) } catch {}; $j.PS = $null
                        & $emitResult ([ordered]@{ Computer=$j.Host; Ping=''; HostStatus='CHECK ERROR'; SecureBoot='?'; Firmware='?'; Disk='?'; Manufacturer='?'; Model='?'; Bios='?'; BiosDate=''; OsBuild='?'; Detail="per-host timeout (${perHostTimeout}s) - possible remote read hang" })
                        $done++; & $send @{ type='progress'; done=$done; total=$jobs.Count }
                    }
                }
            }
            if ($done -lt $jobs.Count) {
                if ($cancelCheck -and (& $cancelCheck)) {
                    foreach ($j in $jobs) {
                        if ($j.PS) {
                            try { [void]$j.PS.BeginStop($null, $null) } catch {}; $j.PS = $null
                            & $emitResult ([ordered]@{ Computer=$j.Host; Ping=''; HostStatus='Cancelled'; SecureBoot='?'; Firmware='?'; Disk='?'; Manufacturer='?'; Model='?'; Bios='?'; BiosDate=''; OsBuild='?'; Detail='cancelled by operator' })
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

    # Tally per verdict from the emitted rows (each row carries its Verdict).
    $verdicts = @('ENABLED','READY TO ENABLE','OFF - UNSUPPORTED OEM','BLOCKED - LEGACY/MBR','CHECK ERROR','OFFLINE','DNS MISMATCH')
    $counts = @{}
    foreach ($v in $verdicts) { $counts[$v] = @($rows | Where-Object { $_.Verdict -eq $v }).Count }
    $ready       = [int]$counts['READY TO ENABLE']
    $enabled     = [int]$counts['ENABLED']
    $blocked     = [int]$counts['BLOCKED - LEGACY/MBR']
    $unsupported = [int]$counts['OFF - UNSUPPORTED OEM']
    $readyList   = @($readyHosts | Sort-Object -Unique)

    & $send @{ type='log'; level='ok'; text="Scan done - ENABLED: $enabled, READY TO ENABLE: $ready, OFF - UNSUPPORTED OEM: $unsupported, BLOCKED - LEGACY/MBR: $blocked, CHECK ERRORS: $($counts['CHECK ERROR']), OFFLINE: $($counts['OFFLINE'])." }
    & $send @{ type='status'; text="Done. $ready ready-to-enable, $enabled already enabled, $blocked blocked, $unsupported unsupported-OEM of $($targets.Count)." }
    return @{
        rows    = @($rows)
        summary = @{
            total       = $targets.Count
            counts      = $counts
            ready       = $ready
            enabled     = $enabled
            blocked     = $blocked
            unsupported = $unsupported
            readyHosts  = $readyList
        }
    }
}

function Get-SbeBool {
    param($Value, [bool]$Default)
    if ($null -eq $Value) { return $Default }
    if ($Value -is [bool]) { return [bool]$Value }
    if ("$Value" -eq '') { return $Default }
    return (@('true','1','yes','on') -contains ([string]$Value).Trim().ToLowerInvariant())
}

# loop58 (item64): fail-CLOSED dry-run parse for the DESTRUCTIVE enable selector. Get-SbeBool
# (shared by attemptOffline/allowEmptyPassword) resolves an unrecognized token to $false, which
# for dry_run means a LIVE firmware write - so a typo ('ture', 'dry', 'y') silently goes live. A
# destructive-mode selector must not fail open: the live path requires an ABSENT value (the
# manifest's documented default=$false) or an EXPLICIT recognized false token. Any present-but-
# unrecognized token stays DRY (safe). Not a change to Get-SbeBool - only this call site is destructive.
function Get-SbeDryRunSafe {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $false }             # absent -> documented default (live)
    if ($Value -is [bool]) { return [bool]$Value }
    $tok = ([string]$Value).Trim().ToLowerInvariant()
    if (@('false','0','no','off') -contains $tok) { return $false }         # explicit LIVE
    return $true                                                            # explicit dry OR unrecognized -> fail SAFE (dry)
}

function Invoke-JanetToolAction {
    param(
        [string]$ActionId,
        [hashtable]$Params,
        [System.Management.Automation.PSCredential]$Credential,
        [scriptblock]$Emit
    )
    $send = { param($e) if ($Emit) { & $Emit $e } }

    # Operator-cancel bridge. The server injects a SYNCHRONIZED hashtable as
    # $Params['__job']; its 'Cancel' flag (set by POST /job/<id>/cancel) lets a
    # cancelled run stop its own in-flight WinRM/SMB children. Outside the server
    # there is no __job -> $cancelCheck returns $false.
    $cancelJob = $null
    if ($Params -and $Params.ContainsKey('__job')) { $cancelJob = $Params['__job'] }
    $cancelCheck = { if ($cancelJob) { try { [bool]$cancelJob['Cancel'] } catch { $false } } else { $false } }

    # Read-only fleet scan (v1.6.0): its own action, no host cap / admin gate.
    if ($ActionId -eq 'scan-secure-boot') {
        return (Invoke-SbeScanAction -Params $Params -Credential $Credential -Emit $Emit)
    }

    if ($ActionId -ne 'enable-secure-boot') {
        & $send @{ type='error'; text="Unknown action '$ActionId'." }
        return @{ rows=@(); summary=@{} }
    }

    $targets = ConvertTo-SecureBootHostList ([string]$Params['targets'])
    if ($targets.Count -eq 0) {
        & $send @{ type='log'; level='warn'; text='No valid targets.' }
        return @{ rows=@(); summary=@{ total=0 } }
    }

    # 50-host cap (original Run-button guard): hard refusal, never truncate.
    if ($targets.Count -gt 50) {
        $extra  = $targets.Count - 50
        $suffix = if ($extra -eq 1) { 'y' } else { 'ies' }
        & $send @{ type='log'; level='err'; text="Maximum 50 machines per run; $($targets.Count) supplied. Remove $extra extra entr$suffix and retry. Nothing was run." }
        return @{ rows=@(); summary=@{ total=$targets.Count; ok=0; failed=0 } }
    }

    # Hostname allow-list (^[A-Za-z0-9._-]+$). Names baked into the SYSTEM payload
    # result path and UNC paths - reject shell metacharacters up front to close the
    # SYSTEM code-injection vector. Any invalid name fails the whole run.
    $badNames = @($targets | Where-Object { $_ -notmatch '^[A-Za-z0-9._-]+$' })
    if ($badNames.Count -gt 0) {
        & $send @{ type='log'; level='err'; text=("These target names are not valid hostnames; nothing was run: " + ($badNames -join ', ') + ". Use only letters, digits, dot, hyphen, and underscore.") }
        return @{ rows=@(); summary=@{ total=$targets.Count; ok=0; failed=0 } }
    }

    # Self-guard (P2-6b, mirrors restart.psm1's dispatch-restart self-exclusion,
    # audit#10): drop the JANET dispatcher host from the run. Secure Boot leaves the
    # target PENDING REBOOT; if that target is the box running JANET, the eventual
    # reboot (or a hung firmware write) can take the JANET server down mid-run. The
    # in-worker DNS-mismatch guard does NOT catch this case (our own name resolves
    # to us, so the compare passes) - drop it here regardless of dry-run mode.
    $selfSkipped = New-Object System.Collections.ArrayList
    $nonSelf     = New-Object System.Collections.ArrayList
    foreach ($t in $targets) {
        if (Test-JanetSbeHostIsSelf $t) { [void]$selfSkipped.Add($t) } else { [void]$nonSelf.Add($t) }
    }
    if ($selfSkipped.Count -gt 0) {
        $targets = $nonSelf.ToArray()
        & $send @{ type='log'; level='warn'; text="Self-guard: dropped the JANET dispatcher host from this run ($($selfSkipped -join ', ')) - Secure Boot leaves a target pending reboot, and a self-reboot would take down the JANET server mid-run." }
        if ($targets.Count -eq 0) {
            & $send @{ type='log'; level='warn'; text='Only target was this dispatcher host - nothing to run.' }
            return @{ rows=@(); summary=@{ total=0; selfSkipped=$selfSkipped.Count } }
        }
    }

    # Dry-run snapshot (atomic in the web action - cannot toggle mid-run).
    $isDry = Get-SbeDryRunSafe $Params['dry_run']   # loop58: fail-closed - unrecognized token stays DRY, never silently live

    # audit 2026-07-23: server-side typed confirm-word gate on the LIVE path (mirrors the
    # pkginstall loop62 DEPLOY gate). The loop-15 ENABLE barrier was manifest-string +
    # view-dialog only, so a direct API call could arm a fleet firmware write with no typed
    # word at all; loop62 retrofitted dhcp (APPLY) and pkginstall (DEPLOY) server-side but
    # secureboot was never retrofitted. Fail-closed: refuse unless the operator typed
    # ENABLE (exactly). Dry run stays ungated (harmless preflight - the loop-15 design).
    if ((-not $isDry) -and ([string]$Params['confirm'] -cne 'ENABLE')) {
        & $send @{ type='log'; level='err'; text='Refused: type ENABLE (exactly) in Confirm to arm the live enable.' }
        return @{ rows=@(); summary=@{ total=0; rejected=$true } }
    }

    # BIOS password + forbidden-char enforcement (only meaningful for live runs).
    $biosPlain = [string]$Params['bios_password']
    if (-not $isDry) {
        foreach ($bad in @(',', "'", '"', '`')) {
            if ($biosPlain.Contains($bad)) {
                & $send @{ type='log'; level='err'; text="The BIOS password contains a character that corrupts the firmware WMI call (comma, single/double quote, or backtick). Remove it and retry." }
                return @{ rows=@(); summary=@{ total=$targets.Count; ok=0; failed=0 } }
            }
        }
        # Empty-password gate (original "No Password - Continue anyway?" confirm).
        # The web form has no modal here, so an explicit allowEmptyPassword opt-in
        # (the view's confirm) replaces the Yes click; without it a blank aborts.
        if ($biosPlain -eq '') {
            if (-not (Get-SbeBool $Params['allowEmptyPassword'] $false)) {
                & $send @{ type='log'; level='err'; text="No BIOS password entered. Tick/confirm 'Allow empty BIOS password' to continue without one (works only if the BIOS has no password set). Nothing was run." }
                return @{ rows=@(); summary=@{ total=$targets.Count; ok=0; failed=0 } }
            }
        }
    }

    # Concurrency. Original cap is 1-10 parallel jobs.
    $threads = 5
    if ($Params['threads']) { [int]::TryParse([string]$Params['threads'], [ref]$threads) | Out-Null }
    $threads = [Math]::Max(1, [Math]::Min(10, $threads))

    # audit 2026-07-23: per-host wall-clock watchdog budget for the harvest loop below,
    # mirroring this module's own scan watchdog ($perHostTimeout in Invoke-SbeScanAction).
    # The live worker's C$ SMB steps (payload drop / icacls lock / result read-back /
    # cleanup) are otherwise unbounded, so one hung SMB call parked the whole run.
    # Budget: session open 15s + 60s ops + the worker's own 90s result poll + SMB margin.
    $perHostTimeout = 300

    $modeLabel = if ($isDry) { 'DRY RUN (preflight only)' } else { 'LIVE firmware write' }
    & $send @{ type='status'; text="Starting Secure Boot enable [$modeLabel] on $($targets.Count) host(s) with $threads thread(s)..." }

    # Build the per-host job set. Live workers each get a unique SYSTEM task name;
    # the worker's own finally unregisters it (finally blocks run to completion
    # under BeginStop on PS 5.1, so cancel does not orphan tasks).
    if ($isDry) {
        $work = $script:SbeDryWorker
        $argFactory = { param($h) ,@($h, $Credential) }
    } else {
        $payload = $script:SbePayload
        $work = $script:SbeLiveWorker
        $argFactory = {
            param($h)
            $taskName = "SBE_$(Get-Random -Maximum 999999)"
            ,@($h, $biosPlain, $payload, $Credential, $taskName)
        }
    }

    $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $threads, $iss, $Host)
    $pool.Open()
    $jobs = New-Object System.Collections.ArrayList
    foreach ($h in $targets) {
        $ps = [powershell]::Create(); $ps.RunspacePool = $pool
        [void]$ps.AddScript($work)
        foreach ($a in (& $argFactory $h)) { [void]$ps.AddArgument($a) }
        [void]$jobs.Add([pscustomobject]@{ Host=$h; PS=$ps; Async=$ps.BeginInvoke(); StartedAt=$null })
    }

    $rows = New-Object System.Collections.ArrayList
    $done = 0; $okCount = 0; $skipCount = 0; $failCount = 0
    $refusedCount = 0   # audit 2026-07-24: safety refusals get their own tally, never "already enabled"
    try {
        while ($done -lt $jobs.Count) {
            # Stamp the per-host clock only up to the pool's real concurrency, in queue
            # order (the scan watchdog's discipline): a PS queued in a saturated
            # RunspacePool reports State='Running' at once, so stamping at ENQUEUE would
            # false-time-out the backlog (~threads*timeout in). audit 2026-07-23.
            $activeCount = @($jobs | Where-Object { $_.PS -and $_.StartedAt }).Count
            foreach ($j in $jobs) {
                if ($j.PS -and -not $j.StartedAt -and $activeCount -lt $pool.GetMaxRunspaces()) { $j.StartedAt = Get-Date; $activeCount++ }
                if ($j.PS -and $j.Async.IsCompleted) {
                    $res = $null
                    try { $res = $j.PS.EndInvoke($j.Async) | Select-Object -First 1 }
                    catch {
                        $res = [ordered]@{ Computer=$j.Host; Status='Error'; Manufacturer='?'; Before='?'; After='?'; SetResult='?'; BitLocker='n/a'; Error="worker error: $($_.Exception.Message)"; Skipped=$false }
                    }
                    try { $j.PS.Dispose() } catch {}
                    $j.PS = $null

                    if ($null -eq $res) {
                        $res = [ordered]@{ Computer=$j.Host; Status='Error'; Manufacturer='?'; Before='?'; After='?'; SetResult='?'; BitLocker='n/a'; Error='Worker returned no data.'; Skipped=$false }
                    }

                    $status = [string]$res.Status
                    $isSkip = ($status -eq 'Skipped')
                    $isOk   = ($status -eq 'Success')
                    $isDryR = ($status -eq 'DryRun')
                    # 'Unknown' = the support state could not be read; NO write was attempted
                    # and the outcome is indeterminate. Bucket it with Skipped (not counted as
                    # OK, not a hard Failure) but keep its DISTINCT 'Unknown' row status.
                    $isUnknown = ($status -eq 'Unknown')
                    # audit 2026-07-24 (P3): a REFUSAL (brick-safety stop / BitLocker suspend that
                    # would not take) is its own outcome - JANET declined to write and nothing
                    # changed. It was previously tallied as an already-enabled skip, inflating the
                    # "N enabled/skipped" line with hosts that still need hands-on work.
                    $isRefused = ($status -eq 'Refused')
                    if ($isOk)          { $okCount++ }
                    elseif ($isSkip)    { $skipCount++ }
                    elseif ($isUnknown) { $skipCount++ }
                    elseif ($isRefused) { $refusedCount++ }
                    elseif (-not $isDryR) { $failCount++ }

                    # loop76 (informative failures): on a real enable failure (not ok/skip/unknown/dry-run),
                    # translate the raw error into an actionable troubleshooting hint - carried in a Hint row
                    # field + appended to the err log; the raw error is preserved. audit 2026-07-24: a
                    # refusal is not a failure - its Error already states the exact precondition to fix.
                    $hint = if ((-not $isOk) -and (-not $isSkip) -and (-not $isUnknown) -and (-not $isRefused) -and (-not $isDryR) -and $res.Error) { Get-JanetTroubleshootHint -Message ([string]$res.Error) -Server ([string]$res.Computer) } else { '' }

                    $row = @{
                        Host         = $res.Computer
                        Status       = $status
                        Manufacturer = [string]$res.Manufacturer
                        Before       = [string]$res.Before
                        After        = [string]$res.After
                        SetResult    = [string]$res.SetResult
                        BitLocker    = [string]$res.BitLocker   # audit 2026-07-24: per-host suspend outcome
                        Error        = [string]$res.Error
                        Hint         = [string]$hint
                    }
                    [void]$rows.Add($row)
                    & $send (@{ type='row' } + $row)

                    # A refusal is amber, not red (nothing broke) and not silent (it needs action).
                    $lvl = if ($isRefused) { 'warn' } elseif ($isOk -or $isSkip -or $isDryR -or $isUnknown) { '' } else { 'err' }
                    $detailText = if ($res.Error) { [string]$res.Error } else { "$status ($($res.Manufacturer))" }
                    if ($res.BitLocker -and -not $res.Error) { $detailText += " | BitLocker: $([string]$res.BitLocker)" }
                    & $send @{ type='log'; level=$lvl; text=(("{0}: {1} - {2}" -f $res.Computer, $status, $detailText) + $(if ($hint) { ' | FIX: ' + $hint } else { '' })) }

                    # JANET audit. Enabling Secure Boot is a security-state change ->
                    # VulnPatched. Success + Skipped (already-enabled) both count;
                    # failures count as Failure. Dry-run preflight rows are NOT logged.
                    if (-not $isDryR) {
                        # audit 2026-07-24: a Refused host is audited Skipped (itemCount 0) - no
                        # write was attempted, so it is neither patched nor a failed attempt.
                        $auditResult = if ($isOk) { 'Success' } elseif ($isSkip -or $isUnknown -or $isRefused) { 'Skipped' } else { 'Failure' }
                        $itemCount   = if ($isOk) { 1 } else { 0 }
                        # Carry the Before->After transition into the audit trail for
                        # non-error rows (HP success stages '<target> (pending reboot)',
                        # Dell may be '(no change detected)') so VulnPatched records the
                        # real firmware state instead of a generic 'Success (Mfr)'. Error
                        # rows keep their failure message as the detail.
                        $auditDetail = if ($res.Error) { [string]$res.Error } else { "$($res.Before) -> $($res.After)" }
                        & $send @{ type='audit'; action='VulnPatched'; target=[string]$res.Computer; result=$auditResult; itemCount=$itemCount; detail=([string]$auditDetail) }
                    }

                    $done++
                    & $send @{ type='progress'; done=$done; total=$jobs.Count }
                }
            }
            # audit 2026-07-23: per-host watchdog (mirrors the scan's) - reap a host that
            # overran its wall clock (hung C$ SMB / WinRM step). BeginStop the local
            # pipeline and null the handle; the worker's finally still runs to completion
            # under BeginStop on PS 5.1, so the SYSTEM task cleanup is not orphaned.
            if ($done -lt $jobs.Count) {
                $nowPh = Get-Date
                foreach ($j in $jobs) {
                    if ($j.PS -and $j.StartedAt -and ($nowPh - $j.StartedAt).TotalSeconds -gt $perHostTimeout) {
                        try { [void]$j.PS.BeginStop($null, $null) } catch {}
                        $j.PS = $null
                        $row = @{ Host=$j.Host; Status='Timeout'; Manufacturer='?'; Before='?'; After='?'; SetResult='?'; BitLocker='n/a'; Error="per-host timeout (${perHostTimeout}s) - hung WinRM/SMB step reaped"; Hint='' }
                        [void]$rows.Add($row)
                        & $send (@{ type='row' } + $row)
                        & $send @{ type='log'; level='err'; text=("{0}: Timeout - per-host timeout ({1}s), in-flight call stopped" -f $j.Host, $perHostTimeout) }
                        # Honest audit (the cancel path's discipline): on a live run the
                        # SYSTEM task may already have started and could still finish the
                        # write, so the outcome is unknown - never record Failure. Skipped
                        # with itemCount 0 reflects "nothing confirmed done".
                        & $send @{ type='audit'; action='VulnPatched'; target=$j.Host; result='Skipped'; itemCount=0; detail="per-host timeout (${perHostTimeout}s); SYSTEM task may have already started (outcome unknown)" }
                        $failCount++; $done++
                        & $send @{ type='progress'; done=$done; total=$jobs.Count }
                    }
                }
            }
            if ($done -lt $jobs.Count) {
                # Cancel BEFORE sleeping: stop every still-running host's in-flight
                # WinRM/SMB child, audit it as abandoned (the DoD trail records the
                # host), terminate the loop, and stop mutating remaining firmware.
                if ($cancelCheck -and (& $cancelCheck)) {
                    foreach ($j in $jobs) {
                        if ($j.PS) {
                            # BeginStop (non-blocking) then NULL the handle. Do NOT
                            # Dispose here - it blocks ~11s per host. The pool
                            # Close/Dispose in finally reclaims the runspaces.
                            try { [void]$j.PS.BeginStop($null, $null) } catch {}
                            $j.PS = $null
                            $row = @{ Host=$j.Host; Status='Error'; Manufacturer='?'; Before='?'; After='?'; SetResult='?'; BitLocker='n/a'; Error='cancelled by operator' }
                            [void]$rows.Add($row)
                            & $send (@{ type='row' } + $row)
                            # Honest audit: on a post-arm cancel the SYSTEM task may
                            # already have started (and could still finish the write),
                            # so the outcome is unknown - never record Failure. Skipped
                            # with itemCount 0 reflects "nothing confirmed done".
                            & $send @{ type='audit'; action='VulnPatched'; target=$j.Host; result='Skipped'; itemCount=0; detail='cancelled by operator (SYSTEM task may have already started; outcome unknown)' }
                            $failCount++; $done++
                        }
                    }
                    & $send @{ type='log'; level='warn'; text='Cancelled by operator; remaining host(s) abandoned (in-flight calls stopped).' }
                    break
                }
                Start-Sleep -Milliseconds 200
            }
        }
    } finally {
        try { $pool.Close(); $pool.Dispose() } catch {}
        $biosPlain = $null
    }

    if ($isDry) {
        & $send @{ type='status'; text="Dry run complete: $($jobs.Count) host(s) probed for TCP (5985/5986/445) reachability + WinRM manufacturer only, $failCount unreachable. A reachable result does NOT confirm the live enable will succeed - UEFI/GPT brick-safety and the BIOS password are only checked during a live run." }
    } else {
        & $send @{ type='status'; text="Done. $okCount enabled, $skipCount already-enabled/skipped, $refusedCount refused (safety), $failCount error/timeout of $($jobs.Count)." }
    }

    return @{
        rows    = @($rows)
        summary = @{ total=$jobs.Count; ok=$okCount; skipped=$skipCount; refused=$refusedCount; failed=$failCount; dryRun=[bool]$isDry }
    }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction
