# =============================================================================
#  JanetTwo.acas.psm1  -  ACAS Nemesis tool engine for J.A.N.E.T. TWO
#  (Re-forked for JANET TWO from the proven JANET ONE engine; cross-checked vs the desktop tool + ui-spec.)
#
#  Ported from Tools\ACAS Nemesis Tool_1.10.10.ps1 (engine reused, WinForms
#  layer dropped). Imports ACAS/Nessus CSV vulnerability exports, matches
#  findings to App Update remediation profiles, combines same-product findings
#  into one card (latest version), dispatches updates in parallel via a runspace
#  pool, schedules and verifies reboots, and pre-flights services - all over
#  WinRM/PSSession. (The standalone KB installer was removed; KBs go through MECM.)
#
#  Contract (identical to JanetTwo.message.psm1):
#    Get-JanetToolManifest                          -> tool + action descriptors
#    Invoke-JanetToolAction -ActionId -Params -Credential -Emit -> { rows; summary }
#  -Emit event shapes consumed by the UI: status / progress / row / log / audit.
#
#  The remote scriptblocks (TCP probe -> bounded Negotiate PSSession ->
#  NetBIOS NTLM fallback -> profile script/verify rehydration, shutdown.exe
#  dispatch, reboot-pending registry check, service start+auto) are lifted
#  verbatim from the original tool's Start-Nem* functions.
# =============================================================================

# -----------------------------------------------------------------------------
#  App Update profile registry (lifted from $script:WptAppUpdateProfiles).
#  Each profile: Desc, Script (update scriptblock), Verify (version probe),
#  optional IsPackage / PackageFolder. PSADT package profiles (IsPackage) are
#  carried for manifest completeness; the controller-side Packages\ staging
#  tree does not exist in the web host, so package deploys report a structured
#  FAIL rather than throwing (see limitations).
# -----------------------------------------------------------------------------

# Builder for the Software Center (CCM_Application Install) profile scripts. The four
# SC profiles ran byte-identical CCM SDK logic; only the match $patterns, $excludes
# and the SKIP noun differed. Built as [scriptblock]::Create() of LITERAL text so the
# .ToString() the remote worker serializes stays self-contained (no closure variables
# to resolve on the target). Output is token-identical to the hand-written blocks.
function New-AcasSoftwareCenterScript {
    param([string[]]$Patterns, [string[]]$Excludes, [string]$Noun)
    $pat = ($Patterns | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ','
    $exc = ($Excludes | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ','
    $body = @'
            try {
                $ns = 'ROOT\ccm\ClientSDK'
                if (-not (Get-CimClass -Namespace $ns -ClassName CCM_Application -ErrorAction SilentlyContinue)) {
                    return 'FAIL: SCCM client (CCM_Application) not present on this host'
                }
                $apps = @(Get-CimInstance -Namespace $ns -ClassName CCM_Application -ErrorAction Stop)
                if ($apps.Count -eq 0) {
                    return 'FAIL: No CCM_Application objects on this host (SCCM client present but empty)'
                }
                $patterns = @(__PATTERNS__)
                $excludes = @(__EXCLUDES__)
                $candidates = @($apps | Where-Object {
                    $n = "$($_.LocalizedDisplayName) $($_.Name)"
                    $m = $false
                    foreach ($p in $patterns) { if ($n -like $p) { $m = $true; break } }
                    if (-not $m) { return $false }
                    foreach ($x in $excludes) { if ($n -like $x) { return $false } }
                    return $true
                })
                if ($candidates.Count -eq 0) {
                    return 'SKIP: No matching __NOUN__ app in Software Center catalog'
                }
                $best = $candidates | Sort-Object `
                    @{Expression={ if ($_.ApplicabilityState -eq 'Applicable') { 0 } else { 1 } }; Descending=$false}, `
                    @{Expression={ [bool]$_.IsMachineTarget }; Descending=$true}, `
                    @{Expression={ if ($_.InstallState -eq 'Installed') { 0 } else { 1 } }; Descending=$false} |
                    Select-Object -First 1
                if ($best.ApplicabilityState -ne 'Applicable') {
                    return "SKIP: '$($best.LocalizedDisplayName)' not Applicable (state=$($best.ApplicabilityState))"
                }
                $param = @{
                    EnforcePreference = [UINT32]0
                    Id                = "$($best.Id)"
                    IsMachineTarget   = [System.Convert]::ToBoolean($best.IsMachineTarget)
                    IsRebootIfNeeded  = $false
                    Priority          = 'High'
                    Revision          = "$($best.Revision)"
                }
                Invoke-CimMethod -Namespace 'root/ccm/clientSDK' -ClassName CCM_Application `
                    -MethodName Install -Arguments $param -ErrorAction Stop | Out-Null
                return "OK (Software Center Install triggered: $($best.LocalizedDisplayName) v$($best.SoftwareVersion))"
            } catch {
                return "FAIL: $($_.Exception.Message)"
            }
'@
    $body = $body.Replace('__PATTERNS__', $pat).Replace('__EXCLUDES__', $exc).Replace('__NOUN__', ($Noun -replace "'", "''"))
    return [scriptblock]::Create($body)
}

# Builder for the Office C2R version-probe Verify blocks (4 profiles ran identical
# registry reads; only the Detail suffix differed). $Detail is literal text embedded
# into the (double-quoted) Detail string, so a "$($p.LastScenario)" sub-expression in
# it is evaluated remotely at probe time. [scriptblock]::Create -> self-contained.
function New-AcasOfficeC2RVerify {
    param([string]$Detail = 'Scenario=$($p.LastScenario)')
    $body = @'
            $cfg = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
            if (-not (Test-Path $cfg)) { return @{ Version = 'n/a'; LastUpdated = 'n/a'; Verified = $null; Detail = 'Office C2R not installed' } }
            $p = Get-ItemProperty -Path $cfg -ErrorAction SilentlyContinue
            $ver = if ($p.VersionToReport) { "$($p.VersionToReport)" } elseif ($p.ClientVersionToReport) { "$($p.ClientVersionToReport)" } else { 'unknown' }
            $key = Get-Item -Path $cfg -ErrorAction SilentlyContinue
            $mod = if ($key) { $key.LastWriteTime } else { $null }
            $modStr = if ($mod) { $mod.ToString('yyyy-MM-dd HH:mm') } else { 'n/a' }
            $verified = if ($mod) { ((Get-Date) - $mod).TotalDays -lt 7 } else { $null }
            return @{ Version = $ver; LastUpdated = $modStr; Verified = $verified; Detail = "__DETAIL__" }
'@
    return [scriptblock]::Create($body.Replace('__DETAIL__', $Detail))
}

# Builder for the Chrome/Edge updater version-probe Verify blocks (4 profiles ran
# identical registry reads; only the client GUID + the two HKLM roots + the Detail
# differed). Roots are joined to \$guid in the generated (double-quoted) path strings.
function New-AcasClientVerify {
    param([string]$Guid, [string]$RootWow, [string]$Root, [string]$Detail = '')
    $body = @'
            $guid = '__GUID__'
            $paths = @(
                "__ROOTWOW__\$guid"
                "__ROOT__\$guid"
            )
            $ver = 'not installed'; $mod = $null
            foreach ($p in $paths) {
                if (Test-Path $p) {
                    $pp = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
                    if ($pp.pv) { $ver = "$($pp.pv)" }
                    $key = Get-Item -Path $p -ErrorAction SilentlyContinue
                    if ($key) { $mod = $key.LastWriteTime }
                    break
                }
            }
            $modStr = if ($mod) { $mod.ToString('yyyy-MM-dd HH:mm') } else { 'n/a' }
            $verified = if ($mod) { ((Get-Date) - $mod).TotalDays -lt 14 } else { $null }
            return @{ Version = $ver; LastUpdated = $modStr; Verified = $verified; Detail = '__DETAIL__' }
'@
    $body = $body.Replace('__GUID__', $Guid).Replace('__ROOTWOW__', $RootWow).Replace('__ROOT__', $Root).Replace('__DETAIL__', $Detail)
    return [scriptblock]::Create($body)
}

$script:AcasUpdateProfiles = @{
    'Microsoft 365 - Force Update' = @{
        Desc   = 'OfficeC2RClient.exe /update user -- silent, force close apps'
        Script = {
            $c2r = 'C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe'
            if (-not (Test-Path $c2r)) { return 'FAIL: OfficeC2RClient.exe not found' }
            $proc = Start-Process -FilePath $c2r -ArgumentList '/update user','/displaylevel=false','/forceappshutdown=true' -Wait -PassThru -NoNewWindow
            return "OK (Office update triggered, exit $($proc.ExitCode))"
        }
        Verify = New-AcasOfficeC2RVerify
    }
    'Microsoft 365 - Update (User Visible)' = @{
        Desc   = 'OfficeC2RClient.exe /update user -- shows progress to user'
        Script = {
            $c2r = 'C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe'
            if (-not (Test-Path $c2r)) { return 'FAIL: OfficeC2RClient.exe not found' }
            $proc = Start-Process -FilePath $c2r -ArgumentList '/update user' -Wait -PassThru -NoNewWindow
            return "OK (Office update triggered, exit $($proc.ExitCode))"
        }
        Verify = New-AcasOfficeC2RVerify
    }
    'Windows Defender - Update Definitions' = @{
        Desc   = 'Update-MpSignature -- pulls latest Defender definitions'
        Script = {
            try {
                Update-MpSignature -ErrorAction Stop
                $def = Get-MpComputerStatus -ErrorAction SilentlyContinue
                $ver = if ($def) { $def.AntivirusSignatureVersion } else { 'unknown' }
                return "OK (Defender definitions updated to $ver)"
            } catch { return "FAIL: $($_.Exception.Message)" }
        }
        Verify = {
            try {
                $def = Get-MpComputerStatus -ErrorAction Stop
                $ver = "$($def.AntivirusSignatureVersion)"
                $last = $def.AntivirusSignatureLastUpdated
                $lastStr = if ($last) { $last.ToString('yyyy-MM-dd HH:mm') } else { 'n/a' }
                $verified = if ($last) { ((Get-Date) - $last).TotalHours -lt 24 } else { $false }
                return @{ Version = $ver; LastUpdated = $lastStr; Verified = $verified; Detail = "Engine=$($def.AMEngineVersion)" }
            } catch {
                return @{ Version = 'error'; LastUpdated = 'n/a'; Verified = $false; Detail = $_.Exception.Message }
            }
        }
    }
    'Google Chrome - Update' = @{
        Desc   = 'GoogleUpdate.exe /ua /installsource scheduler'
        Script = {
            $exe = 'C:\Program Files (x86)\Google\Update\GoogleUpdate.exe'
            if (-not (Test-Path $exe)) { $exe = 'C:\Program Files\Google\Update\GoogleUpdate.exe' }
            if (-not (Test-Path $exe)) { return 'FAIL: GoogleUpdate.exe not found' }
            $proc = Start-Process -FilePath $exe -ArgumentList '/ua /installsource scheduler' -Wait -PassThru -NoNewWindow
            return "OK (Chrome update triggered, exit $($proc.ExitCode))"
        }
        Verify = New-AcasClientVerify -Guid '{8A69D345-D564-463c-AFF1-A69D9E530F96}' -RootWow 'HKLM:\SOFTWARE\WOW6432Node\Google\Update\Clients' -Root 'HKLM:\SOFTWARE\Google\Update\Clients'
    }
    'Microsoft Edge - Update' = @{
        Desc   = 'MicrosoftEdgeUpdate.exe /ua /installsource scheduler'
        Script = {
            $exe = 'C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe'
            if (-not (Test-Path $exe)) { return 'FAIL: MicrosoftEdgeUpdate.exe not found' }
            $proc = Start-Process -FilePath $exe -ArgumentList '/ua /installsource scheduler' -Wait -PassThru -NoNewWindow
            return "OK (Edge update triggered, exit $($proc.ExitCode))"
        }
        Verify = New-AcasClientVerify -Guid '{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}' -RootWow 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients' -Root 'HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients'
    }
    'Microsoft 365 - Force Update (SYSTEM task)' = @{
        Desc = 'Scheduled task runs OfficeC2RClient.exe as SYSTEM with /forceappshutdown=true. Fallback when operator-context runs fail (open sessions, Kerberos, delegation).'
        Script = {
            $exe = 'C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe'
            if (-not (Test-Path $exe)) { return 'FAIL: OfficeC2RClient.exe not found' }
            $arguments = '/update user /displaylevel=false /forceappshutdown=true'
            $taskName  = 'AcasNemesis_OfficeC2R_Update'
            try {
                $stale = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                if ($stale) {
                    try { Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue } catch {}
                    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
                }
                $action  = New-ScheduledTaskAction -Execute $exe -Argument $arguments
                $trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddYears(10))
                [void](Register-ScheduledTask -Action $action -Trigger $trigger `
                    -TaskName $taskName -User 'System' -RunLevel Highest -ErrorAction Stop)
                Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
                $deadline = (Get-Date).AddMinutes(10)
                $elapsed  = 0
                $stillRunning = $true
                while ((Get-Date) -lt $deadline) {
                    $t = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                    if (-not $t) { $stillRunning = $false; break }
                    if ($t.State -eq 'Ready') { $stillRunning = $false; break }
                    Start-Sleep -Seconds 5
                    $elapsed += 5
                }
                try { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop } catch {}
                if ($stillRunning) { return "FAIL: SYSTEM task still running after 600s (unregistered)" }
                return "OK (SYSTEM task completed in ${elapsed}s)"
            } catch {
                try { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}
                return "FAIL: $($_.Exception.Message)"
            }
        }
        Verify = New-AcasOfficeC2RVerify -Detail 'Scenario=$($p.LastScenario); SYSTEM-task variant'
    }
    'Microsoft 365 - Software Center' = @{
        Desc = 'CCM_Application Install via SCCM client SDK. Targets the M365 Apps / Office 365 ProPlus catalog entry. Use when OfficeC2RClient.exe is wedged or you want SCCM-controlled rollout.'
        Script = New-AcasSoftwareCenterScript -Patterns @('*Microsoft 365 Apps*','*Office 365 ProPlus*','*Microsoft 365*','*Office 365*','*Microsoft Office Pro*','*M365 Apps*') -Excludes @('*Skype*','*Teams*','*OneDrive*','*OneNote*','*Visio*','*Project*','*Language Pack*','*Proofing*','*Web Apps*','*Remove*','*Uninstall*') -Noun 'Office / M365'
        Verify = New-AcasOfficeC2RVerify -Detail 'Scenario=$($p.LastScenario); via Software Center'
    }
    'Google Chrome - Software Center' = @{
        Desc = 'CCM_Application Install via SCCM client SDK. Use when GoogleUpdate.exe is broken / absent or you want to honor the Software Center deployment ring.'
        Script = New-AcasSoftwareCenterScript -Patterns @('*Google Chrome*') -Excludes @('*Update*','*Helper*','*Sync*') -Noun 'Chrome'
        Verify = New-AcasClientVerify -Guid '{8A69D345-D564-463c-AFF1-A69D9E530F96}' -RootWow 'HKLM:\SOFTWARE\WOW6432Node\Google\Update\Clients' -Root 'HKLM:\SOFTWARE\Google\Update\Clients' -Detail 'via Software Center'
    }
    'Microsoft Edge - Software Center' = @{
        Desc = 'CCM_Application Install via SCCM client SDK. Use when MicrosoftEdgeUpdate.exe is broken / absent or you want to honor the Software Center deployment ring.'
        Script = New-AcasSoftwareCenterScript -Patterns @('*Microsoft Edge*') -Excludes @('*Update*','*WebView*','*Helper*','*Beta*','*Dev*','*Canary*') -Noun 'Edge'
        Verify = New-AcasClientVerify -Guid '{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}' -RootWow 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients' -Root 'HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients' -Detail 'via Software Center'
    }
    'Oracle Java - Software Center' = @{
        Desc = 'CCM_Application Install via SCCM client SDK. Triggers the Software Center Java package install - use when Oracle Java SE CPU vulnerabilities are flagged and a Java app is published in SC.'
        Script = New-AcasSoftwareCenterScript -Patterns @('*Java*','*Oracle JRE*') -Excludes @('*Helper*','*Auto Update*','*Update Scheduler*','*Web Start*') -Noun 'Java'
        Verify = {
            $paths = @(
                'HKLM:\SOFTWARE\JavaSoft\Java Runtime Environment'
                'HKLM:\SOFTWARE\WOW6432Node\JavaSoft\Java Runtime Environment'
                'HKLM:\SOFTWARE\JavaSoft\JRE'
                'HKLM:\SOFTWARE\WOW6432Node\JavaSoft\JRE'
            )
            $ver = 'not installed'; $mod = $null; $javaHome = ''
            foreach ($p in $paths) {
                if (Test-Path $p) {
                    $pp = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
                    $cur = if ($pp -and $pp.CurrentVersion) { "$($pp.CurrentVersion)" } else { '' }
                    if (-not $cur) { continue }
                    $sub = Join-Path $p $cur
                    if (Test-Path $sub) {
                        $spp = Get-ItemProperty -Path $sub -ErrorAction SilentlyContinue
                        if ($spp -and $spp.JavaHome) { $javaHome = "$($spp.JavaHome)" }
                        $skey = Get-Item -Path $sub -ErrorAction SilentlyContinue
                        if ($skey) { $mod = $skey.LastWriteTime }
                    }
                    $ver = $cur
                    if ($javaHome) {
                        $jvm = Join-Path $javaHome 'bin\server\jvm.dll'
                        if (-not (Test-Path -LiteralPath $jvm)) { $jvm = Join-Path $javaHome 'bin\client\jvm.dll' }
                        if (Test-Path -LiteralPath $jvm) {
                            try {
                                $fi = (Get-Item -LiteralPath $jvm -ErrorAction Stop).VersionInfo
                                if ($fi.ProductVersion) { $ver = "$($fi.ProductVersion)" }
                                elseif ($fi.FileVersion) { $ver = "$($fi.FileVersion)" }
                            } catch {}
                        }
                    }
                    break
                }
            }
            $modStr = if ($mod) { $mod.ToString('yyyy-MM-dd HH:mm') } else { 'n/a' }
            $verified = if ($mod) { ((Get-Date) - $mod).TotalDays -lt 30 } else { $null }
            $detailStr = if ($javaHome) { "home: $javaHome" } else { 'via Software Center' }
            return @{ Version = $ver; LastUpdated = $modStr; Verified = $verified; Detail = $detailStr }
        }
    }
    'Microsoft Store - Update Apps' = @{
        Desc = 'Trigger a Microsoft Store update scan (EXPERIMENTAL). Covers Windows App (Remote Desktop) and other MS-Store apps.'
        Script = {
            try {
                $obj = Get-CimInstance -Namespace 'root/cimv2/mdm/dmmap' `
                                       -ClassName  'MDM_EnterpriseModernAppManagement_AppManagement01' `
                                       -ErrorAction Stop
                if (-not $obj) { return 'FAIL: MDM AppManagement CIM class not available' }
                [void]($obj | Invoke-CimMethod -MethodName 'UpdateScanMethod' -ErrorAction Stop)
                return 'OK (Store UpdateScanMethod triggered)'
            } catch {
                return "FAIL: $($_.Exception.Message)"
            }
        }
        Verify = {
            try {
                $pkg = Get-AppxPackage -AllUsers -Name 'Microsoft.WindowsApp*' -ErrorAction SilentlyContinue |
                       Select-Object -First 1
                if (-not $pkg) {
                    return @{ Version = 'not installed'; LastUpdated = 'n/a'; Verified = $null; Detail = 'Microsoft.WindowsApp package not found' }
                }
                $ver = "$($pkg.Version)"
                $inst = Get-Item -Path $pkg.InstallLocation -ErrorAction SilentlyContinue
                $mod = if ($inst) { $inst.LastWriteTime } else { $null }
                $modStr = if ($mod) { $mod.ToString('yyyy-MM-dd HH:mm') } else { 'n/a' }
                $verified = if ($mod) { ((Get-Date) - $mod).TotalDays -lt 14 } else { $null }
                return @{ Version = $ver; LastUpdated = $modStr; Verified = $verified; Detail = 'EXPERIMENTAL' }
            } catch {
                return @{ Version = 'error'; LastUpdated = 'n/a'; Verified = $false; Detail = $_.Exception.Message }
            }
        }
    }
    'Windows Unquoted Service Path - Remediate' = @{
        Desc   = 'Find services whose ImagePath has spaces and no surrounding quotes, then rewrite with quotes around the exe (args preserved). Backs up original value to HKLM:\SOFTWARE\JANET\Nemesis\UnquotedSvcPath. Clears Tenable plugin 63155.'
        Script = {
            $svcRoot    = 'HKLM:\SYSTEM\CurrentControlSet\Services'
            $backupRoot = 'HKLM:\SOFTWARE\JANET\Nemesis\UnquotedSvcPath'
            if (-not (Test-Path $svcRoot)) { return 'FAIL: services hive not found' }
            try {
                if (-not (Test-Path $backupRoot)) { New-Item -Path $backupRoot -Force -EA Stop | Out-Null }
            } catch { return "FAIL: cannot create backup root: $($_.Exception.Message)" }

            $fixed   = New-Object System.Collections.Generic.List[string]
            $skipped = 0
            $errors  = New-Object System.Collections.Generic.List[string]
            $exeRe = [regex]'(?i)^(.+?\.exe)(\s.*)?$'

            foreach ($svc in Get-ChildItem -LiteralPath $svcRoot -EA SilentlyContinue) {
                $svcName = $svc.PSChildName
                $img = $null
                try { $img = (Get-ItemProperty -LiteralPath $svc.PSPath -Name ImagePath -EA Stop).ImagePath }
                catch { continue }
                if ([string]::IsNullOrWhiteSpace($img)) { continue }

                $trim = $img.TrimStart()
                if ($trim.StartsWith('"')) { $skipped++; continue }

                $m = $exeRe.Match($trim)
                if (-not $m.Success) { $skipped++; continue }
                $exePart  = $m.Groups[1].Value
                $argsPart = if ($m.Groups[2].Success) { $m.Groups[2].Value } else { '' }
                if ($exePart -notmatch ' ') { $skipped++; continue }

                $newImg = '"' + $exePart + '"' + $argsPart
                if ($newImg -eq $img) { $skipped++; continue }

                $kind = $null
                try { $kind = (Get-Item -LiteralPath $svc.PSPath).GetValueKind('ImagePath') } catch {}
                $type = if ($kind -eq [Microsoft.Win32.RegistryValueKind]::ExpandString) { 'ExpandString' } else { 'String' }

                try {
                    $bk = Join-Path $backupRoot $svcName
                    if (-not (Test-Path $bk)) { New-Item -Path $bk -Force -EA Stop | Out-Null }
                    Set-ItemProperty -LiteralPath $bk -Name 'OriginalImagePath' -Value $img    -Type String -Force -EA Stop
                    Set-ItemProperty -LiteralPath $bk -Name 'FixedTimestamp'    -Value (Get-Date -Format 's') -Type String -Force -EA Stop
                    Set-ItemProperty -LiteralPath $bk -Name 'OriginalKind'      -Value "$kind" -Type String -Force -EA Stop
                    Set-ItemProperty -LiteralPath $svc.PSPath -Name ImagePath   -Value $newImg -Type $type   -Force -EA Stop
                    $fixed.Add($svcName) | Out-Null
                } catch {
                    $errors.Add("${svcName}: $($_.Exception.Message)") | Out-Null
                }
            }

            $summary = "fixed=$($fixed.Count) skipped=$skipped errors=$($errors.Count)"
            if ($errors.Count -gt 0) { return "FAIL ($summary; first error: $($errors[0]))" }
            if ($fixed.Count -eq 0)  { return "OK (nothing to fix; $summary)" }
            return "OK ($summary; fixed: $((($fixed | Sort-Object) -join ', ')))"
        }
        Verify = {
            $svcRoot    = 'HKLM:\SYSTEM\CurrentControlSet\Services'
            $backupRoot = 'HKLM:\SOFTWARE\JANET\Nemesis\UnquotedSvcPath'
            $exeRe      = [regex]'(?i)^(.+?\.exe)(\s.*)?$'
            $remaining  = New-Object System.Collections.Generic.List[string]

            foreach ($svc in Get-ChildItem -LiteralPath $svcRoot -EA SilentlyContinue) {
                $img = $null
                try { $img = (Get-ItemProperty -LiteralPath $svc.PSPath -Name ImagePath -EA Stop).ImagePath }
                catch { continue }
                if ([string]::IsNullOrWhiteSpace($img)) { continue }
                $trim = $img.TrimStart()
                if ($trim.StartsWith('"')) { continue }
                $m = $exeRe.Match($trim)
                if (-not $m.Success) { continue }
                if ($m.Groups[1].Value -notmatch ' ') { continue }
                $remaining.Add($svc.PSChildName) | Out-Null
            }

            $lastFix = 'n/a'
            if (Test-Path $backupRoot) {
                $newest = Get-ChildItem -LiteralPath $backupRoot -EA SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ($newest) { $lastFix = $newest.LastWriteTime.ToString('yyyy-MM-dd HH:mm') }
            }

            return @{
                Version     = "Unquoted remaining: $($remaining.Count)"
                LastUpdated = $lastFix
                Verified    = ($remaining.Count -eq 0)
                Detail      = if ($remaining.Count -eq 0) { 'All service ImagePath values are quoted or have no spaces in the exe portion.' } else { 'Still unquoted: ' + (($remaining | Sort-Object) -join ', ') }
            }
        }
    }
    'MSXML 4.0 - Uninstall' = @{
        Desc   = 'MsiExec /x of any "MSXML 4.0*" product found in the Uninstall registry (HKLM 64-bit + WOW6432Node). Silent. Clears Tenable plugin 62758. No reboot expected.'
        Script = {
            $hives = @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
            )
            $found = New-Object System.Collections.Generic.List[object]
            foreach ($hive in $hives) {
                if (-not (Test-Path $hive)) { continue }
                foreach ($k in Get-ChildItem -LiteralPath $hive -EA SilentlyContinue) {
                    $p = $null
                    try { $p = Get-ItemProperty -LiteralPath $k.PSPath -EA Stop } catch { continue }
                    if ($p.DisplayName -like 'MSXML 4.0*') {
                        $found.Add([pscustomobject]@{
                            Name = "$($p.DisplayName)"
                            Ver  = "$($p.DisplayVersion)"
                            GUID = "$($k.PSChildName)"
                        }) | Out-Null
                    }
                }
            }
            if ($found.Count -eq 0) { return 'OK (no MSXML 4.0 products installed)' }

            $removed = New-Object System.Collections.Generic.List[string]
            $errors  = New-Object System.Collections.Generic.List[string]
            foreach ($f in $found) {
                if ($f.GUID -notmatch '^\{[0-9A-Fa-f-]+\}$') {
                    $errors.Add("$($f.Name): unsupported product key '$($f.GUID)' (not a GUID, skipping)") | Out-Null
                    continue
                }
                try {
                    $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/x', $f.GUID, '/qn', '/norestart') -Wait -PassThru -NoNewWindow -EA Stop
                    if ($proc.ExitCode -in 0,1605,3010) {
                        $removed.Add("$($f.Name) [$($f.GUID)] (exit $($proc.ExitCode))") | Out-Null
                    } else {
                        $errors.Add("$($f.Name) [$($f.GUID)]: msiexec exit $($proc.ExitCode)") | Out-Null
                    }
                } catch { $errors.Add("$($f.Name): $($_.Exception.Message)") | Out-Null }
            }

            $summary = "removed=$($removed.Count) errors=$($errors.Count)"
            if ($errors.Count -gt 0) { return "FAIL ($summary; first error: $($errors[0]))" }
            return "OK ($summary; $($removed -join '; '))"
        }
        Verify = {
            $hives = @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
            )
            $names = New-Object System.Collections.Generic.List[string]
            foreach ($hive in $hives) {
                if (-not (Test-Path $hive)) { continue }
                foreach ($k in Get-ChildItem -LiteralPath $hive -EA SilentlyContinue) {
                    $p = $null
                    try { $p = Get-ItemProperty -LiteralPath $k.PSPath -EA Stop } catch { continue }
                    if ($p.DisplayName -like 'MSXML 4.0*') {
                        $names.Add("$($p.DisplayName) $($p.DisplayVersion)") | Out-Null
                    }
                }
            }
            return @{
                Version     = if ($names.Count -gt 0) { ($names | Sort-Object -Unique) -join '; ' } else { 'none' }
                LastUpdated = 'n/a'
                Verified    = ($names.Count -eq 0)
                Detail      = if ($names.Count -eq 0) { 'No MSXML 4.0 products in Uninstall registry' } else { "$($names.Count) MSXML 4.0 entries still installed" }
            }
        }
    }
    'Apache Log4j - Replace Vulnerable Jars' = @{
        # NeedsStaging: the JANET TWO host stages the controller-side 2.25.4 jars
        # into each target session (Copy-Item -ToSession) and rewrites $sourceShare
        # to that local temp before running - so this auto-runs when the jars are
        # present where the host can read them (default: the desktop staging share,
        # or an operator-set source path).
        Desc   = 'Replace log4j-api/core jars with 2.25.4 across HID + Adobe lib paths (recursive). Auto-runs when the 2.25.4 jars are staged where the JANET TWO host can read them (host copies them into each session).'
        NeedsStaging = $true
        Script = {
            $sourceShare = '\\dm-tn-01\sh-usafe-automation$\JANET\Packages\Log4j\NewFiles'
            $newApi      = 'log4j-api-2.25.4.jar'
            $newCore     = 'log4j-core-2.25.4.jar'
            $targets     = @(
                @{ Path='C:\Program Files\HID Global\Credential Management Client\lib'; Service='HIDCredentialManagementClient' }
                @{ Path='C:\Program Files\Adobe\Adobe Experience Manager Forms Designer\Java\libs'; Service='AdobeExperienceManagerFormsDesigner' }
            )
            $srcApi  = Join-Path $sourceShare $newApi
            $srcCore = Join-Path $sourceShare $newCore
            if (-not (Test-Path -LiteralPath $srcApi))  { return "FAIL: source jar missing: $srcApi" }
            if (-not (Test-Path -LiteralPath $srcCore)) { return "FAIL: source jar missing: $srcCore" }

            $liveReplaced    = 0
            $archiveDeleted  = 0
            $skippedRoots    = 0
            $skippedCurrent  = 0
            $errors          = New-Object System.Collections.Generic.List[string]

            foreach ($t in $targets) {
                $libPath = $t.Path
                if (-not (Test-Path -LiteralPath $libPath)) { $skippedRoots++; continue }
                try {
                    $allJars = @(Get-ChildItem -LiteralPath $libPath -Filter 'log4j-*.jar' -Recurse -File -Force -ErrorAction SilentlyContinue)
                } catch { $allJars = @() }

                $relevant = @($allJars | Where-Object {
                    $_.Name -match '^log4j-(api|core)-' -and $_.Name -like '*.jar'
                })
                if ($relevant.Count -eq 0) { $skippedRoots++; continue }

                $current = @($relevant | Where-Object { $_.Name -eq $newApi -or $_.Name -eq $newCore })
                $stale   = @($relevant | Where-Object { $_.Name -ne $newApi -and $_.Name -ne $newCore })
                $skippedCurrent += $current.Count

                $archiveStale = @($stale | Where-Object { $_.FullName -like '*\Backup_*\*' })
                $liveStale    = @($stale | Where-Object { $_.FullName -notlike '*\Backup_*\*' })

                $wasRunning = $false
                if ($liveStale.Count -gt 0) {
                    $svc = Get-Service -Name $t.Service -ErrorAction SilentlyContinue
                    $wasRunning = ($svc -and $svc.Status -eq 'Running')
                    if ($wasRunning) {
                        try { Stop-Service -Name $t.Service -Force -ErrorAction Stop }
                        catch { $errors.Add("$($t.Service) stop failed: $($_.Exception.Message)") | Out-Null }
                    }
                }

                try {
                    if ($liveStale.Count -gt 0) {
                        $backupDir = Join-Path $libPath ("Backup_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
                        New-Item -Path $backupDir -ItemType Directory -Force -ErrorAction Stop | Out-Null

                        # Back up the stale live jars first (copy only - do NOT remove yet).
                        foreach ($f in $liveStale) {
                            try {
                                Copy-Item -LiteralPath $f.FullName -Destination $backupDir -Force -ErrorAction Stop
                            } catch { $errors.Add("$($f.FullName) backup failed: $($_.Exception.Message)") | Out-Null }
                        }

                        # Copy the replacement jars in BEFORE deleting the originals, so a
                        # failed copy can never leave the lib dir with no log4j jars.
                        $rootApi  = Join-Path $libPath $newApi
                        $rootCore = Join-Path $libPath $newCore
                        $copyOk = $true
                        try { Copy-Item -LiteralPath $srcApi  -Destination $rootApi  -Force -ErrorAction Stop }
                        catch { $copyOk = $false; $errors.Add("$rootApi copy failed: $($_.Exception.Message)") | Out-Null }
                        try { Copy-Item -LiteralPath $srcCore -Destination $rootCore -Force -ErrorAction Stop }
                        catch { $copyOk = $false; $errors.Add("$rootCore copy failed: $($_.Exception.Message)") | Out-Null }

                        # Only remove the stale live jars once both replacements are confirmed on disk.
                        if ($copyOk -and (Test-Path -LiteralPath $rootApi) -and (Test-Path -LiteralPath $rootCore)) {
                            foreach ($f in $liveStale) {
                                try { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop }
                                catch { $errors.Add("$($f.FullName) remove failed: $($_.Exception.Message)") | Out-Null }
                            }
                            $liveReplaced++
                        } else {
                            $errors.Add("${libPath}: replacement jars not confirmed present - stale jars left in place (lib dir not left jar-less)") | Out-Null
                        }
                    }

                    foreach ($f in $archiveStale) {
                        try {
                            Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop
                            $archiveDeleted++
                        } catch { $errors.Add("$($f.FullName) delete failed: $($_.Exception.Message)") | Out-Null }
                    }
                } catch {
                    $errors.Add("$libPath swap failed: $($_.Exception.Message)") | Out-Null
                } finally {
                    if ($wasRunning) {
                        try { Start-Service -Name $t.Service -ErrorAction Stop }
                        catch { $errors.Add("$($t.Service) restart failed: $($_.Exception.Message)") | Out-Null }
                    }
                }
            }

            $summary = "live=$liveReplaced archive=$archiveDeleted current=$skippedCurrent rootsSkipped=$skippedRoots"
            if ($errors.Count -gt 0) {
                return "FAIL ($summary; errors: " + ($errors -join '; ') + ')'
            }
            if ($liveReplaced -eq 0 -and $archiveDeleted -eq 0) {
                return "OK (nothing to do; $summary)"
            }
            return "OK ($summary)"
        }
        Verify = {
            $targets = @(
                'C:\Program Files\HID Global\Credential Management Client\lib'
                'C:\Program Files\Adobe\Adobe Experience Manager Forms Designer\Java\libs'
            )
            $found    = New-Object System.Collections.Generic.List[string]
            $vulns    = New-Object System.Collections.Generic.List[string]
            $newest   = $null

            foreach ($p in $targets) {
                if (-not (Test-Path -LiteralPath $p)) { continue }
                $jars = @(Get-ChildItem -LiteralPath $p -Filter 'log4j-*.jar' -Recurse -File -Force -ErrorAction SilentlyContinue)
                foreach ($j in $jars) {
                    $found.Add("$($j.Name)") | Out-Null
                    if ($j.Name -notmatch '^log4j-(api|core)-2\.25\.4\.jar$') {
                        $vulns.Add("$($j.FullName)") | Out-Null
                    }
                    if ($null -eq $newest -or $j.LastWriteTime -gt $newest) { $newest = $j.LastWriteTime }
                }
            }

            if ($found.Count -eq 0) {
                return @{ Version='none'; LastUpdated='n/a'; Verified=$true; Detail='No log4j jars in target paths' }
            }

            $verStr  = ($found | Sort-Object -Unique) -join ', '
            $modStr  = if ($newest) { $newest.ToString('yyyy-MM-dd HH:mm') } else { 'n/a' }
            $verified = ($vulns.Count -eq 0)
            $detail  = if ($vulns.Count -gt 0) { "STILL-VULNERABLE ($($vulns.Count)): " + (($vulns | Sort-Object -Unique) -join '; ') } else { 'All jars at 2.25.4 (recursive scan)' }
            return @{ Version=$verStr; LastUpdated=$modStr; Verified=$verified; Detail=$detail }
        }
    }
    'Tenable Nessus Agent - Package Deploy' = @{
        # PSADT package install needs the controller-side Packages\ staging tree,
        # which the JANET TWO web host does not carry. IsPackage profiles are
        # surfaced as a coverage gap by auto-patch (NeedsStaging) and return a
        # structured FAIL if dispatched directly. Verify still works in-session.
        Desc          = 'PSADT package install (Tenable Nessus Agent). NOTE: needs controller-side Packages\ staging; not auto-runnable from the JANET TWO host.'
        IsPackage     = $true
        PackageFolder = 'NIPR_Tenable Nessus Agent_11.1.3'
        Script        = $null
        Verify = {
            $tenPaths = @(
                'HKLM:\SOFTWARE\Tenable\Tenable Nessus Agent\Tenable Nessus Agent'
                'HKLM:\SOFTWARE\WOW6432Node\Tenable\Tenable Nessus Agent\Tenable Nessus Agent'
                'HKLM:\SOFTWARE\Tenable\Tenable Nessus Agent'
                'HKLM:\SOFTWARE\WOW6432Node\Tenable\Tenable Nessus Agent'
            )
            $ver = 'not installed'
            $mod = $null
            foreach ($p in $tenPaths) {
                if (Test-Path -LiteralPath $p) {
                    $pp = Get-ItemProperty -LiteralPath $p -ErrorAction SilentlyContinue
                    if ($pp -and $pp.PSObject.Properties['nessus_agent_ver'] -and $pp.nessus_agent_ver) {
                        $ver = "$($pp.nessus_agent_ver)"
                    } elseif ($pp -and $pp.PSObject.Properties['Version'] -and $pp.Version) {
                        $ver = "$($pp.Version)"
                    }
                    $key = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue
                    if ($key) { $mod = $key.LastWriteTime }
                    if ($ver -ne 'not installed') { break }
                }
            }
            if ($ver -eq 'not installed') {
                $uninstRoots = @(
                    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
                    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
                )
                foreach ($u in $uninstRoots) {
                    if (-not (Test-Path -LiteralPath $u)) { continue }
                    try {
                        $hit = Get-ChildItem -LiteralPath $u -ErrorAction SilentlyContinue |
                            Where-Object {
                                $dn = $_.GetValue('DisplayName')
                                $dn -and ($dn -like '*Nessus Agent*' -or $dn -like '*Tenable*Agent*')
                            } |
                            Select-Object -First 1
                        if ($hit) {
                            $dv = $hit.GetValue('DisplayVersion')
                            if ($dv) { $ver = [string]$dv }
                            $instDate = $hit.GetValue('InstallDate')
                            if ($instDate -and -not $mod) {
                                try { $mod = [datetime]::ParseExact("$instDate", 'yyyyMMdd', [System.Globalization.CultureInfo]::InvariantCulture) } catch {}
                            }
                            break
                        }
                    } catch {}
                }
            }
            $modStr = if ($mod -is [datetime]) { $mod.ToString('yyyy-MM-dd HH:mm') } else { 'n/a' }
            $verified = if ($ver -ne 'not installed') { $true } else { $false }
            $detail = if ($ver -eq 'not installed') { 'Nessus Agent not detected via registry' } else { 'via Tenable registry / Uninstall key' }
            return @{ Version = $ver; LastUpdated = $modStr; Verified = $verified; Detail = $detail }
        }
    }
    'Edge STIG - Disable Search Engine Import' = @{
        Desc   = 'Set HKLM:\SOFTWARE\Policies\Microsoft\Edge\ImportSearchEngine = 0 (DWord). Clears DISA Edge STIG EDGE-00-000022 / the Tenable noCCE finding. No reboot; effective at next Edge launch.'
        Script = {
            $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            try {
                if (-not (Test-Path -LiteralPath $key)) { New-Item -Path $key -Force -EA Stop | Out-Null }
                New-ItemProperty -LiteralPath $key -Name 'ImportSearchEngine' -Value 0 -PropertyType DWord -Force -EA Stop | Out-Null
                $now = (Get-ItemProperty -LiteralPath $key -Name 'ImportSearchEngine' -EA Stop).ImportSearchEngine
                if ([int]$now -eq 0) { return 'OK (ImportSearchEngine=0 set)' }
                return "FAIL: readback was $now after write"
            } catch { return "FAIL: $($_.Exception.Message)" }
        }
        Verify = {
            $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            $val = $null
            try { $val = (Get-ItemProperty -LiteralPath $key -Name 'ImportSearchEngine' -EA Stop).ImportSearchEngine } catch {}
            $mod = $null
            try { if (Test-Path -LiteralPath $key) { $mod = (Get-Item -LiteralPath $key -EA SilentlyContinue).LastWriteTime } } catch {}
            $modStr = if ($mod -is [datetime]) { $mod.ToString('yyyy-MM-dd HH:mm') } else { 'n/a' }
            $isOk   = ($null -ne $val -and [int]$val -eq 0)
            return @{
                Version     = if ($null -eq $val) { 'not set' } else { "ImportSearchEngine=$val" }
                LastUpdated = $modStr
                Verified    = $isOk
                Detail      = if ($isOk) { 'STIG EDGE-00-000022 satisfied (import disabled)' } else { 'Value missing or non-zero -- STIG not satisfied' }
            }
        }
    }
}

# -----------------------------------------------------------------------------
#  ACAS CSV column mapping (lifted from Config.acasImport.ACAS_Default).
# -----------------------------------------------------------------------------
$script:AcasColumnMap = @{
    dnsName    = 'DNS Name'
    netbios    = 'NetBIOS Name'
    ip         = 'IP Address'
    pluginId   = 'Plugin'
    pluginName = 'Plugin Name'
    severity   = 'Severity'
    cvssV3     = 'CVSS v3.0 Base Score'
    cve        = 'CVE'
    solution   = 'Steps to Remediate'
    firstSeen  = 'First Discovered'
    lastSeen   = 'Last Observed'
}

function Get-JanetToolManifest {
    @{
        id       = 'acas'
        name     = 'ACAS Nemesis'
        version  = '1.10.12'
        category = 'Patching'
        summary  = 'Import ACAS/Nessus CSV findings, combine same-product vulnerabilities, push App Update remediations, and schedule/verify reboots + pre-flight services across many hosts over WinRM.'
        actions  = @(
            @{
                id          = 'import-acas'
                label       = 'Import ACAS CSV'
                description  = 'Parse one or more ACAS/Nessus CSV exports, normalize and de-duplicate target hostnames, drop msek-* server findings, and summarize findings per host.'
                kind         = 'table'
                destructive  = $false
                columns      = @('Host','Findings Added','Severity (max)','Plugins','Servers Skipped')
                inputs       = @(
                    @{ name='csvPaths'; label='ACAS CSV file'; type='file'; filter='CSV files (*.csv)|*.csv|All files (*.*)|*.*'; required=$true }
                )
            },
            @{
                id          = 'analyze-remediation'
                label       = 'Analyze (What Can I Patch?)'
                description  = 'Parse the ACAS CSV, group findings by plugin, and classify each: Patchable (a matched App Update profile exists), Experimental, Reboot, Unpatchable, or Not Updatable. Shows the matched profile and affected host count per vulnerability. Read-only - no remote calls, no credential. Run this first to preview what Auto-Patch will do.'
                kind         = 'table'
                destructive  = $false
                columns      = @('Category','Plugin','Severity','Hosts','Matched Profile','Auto-Runnable','CVEs')
                inputs       = @(
                    @{ name='csvPaths'; label='ACAS CSV file'; type='file'; filter='CSV files (*.csv)|*.csv|All files (*.*)|*.*'; required=$true }
                )
            },
            @{
                id          = 'auto-patch'
                label       = 'Auto-Patch From CSV'
                description  = 'Import the ACAS CSV and automatically push the matched remediation to every affected host: group findings by plugin, match each Patchable vulnerability to its App Update profile, de-duplicate (profile, host) work, and run it in parallel over WinRM. Coverage gaps (Reboot / Unpatchable / package-staged) are listed but not run. Verify-only does a dry check without changing anything.'
                kind         = 'stream-table'
                destructive  = $true
                columns      = @('Host','Profile','Result','Version Before','Version After','Timestamp','Detail')
                inputs       = @(
                    @{ name='csvPaths';            label='ACAS CSV file'; type='file'; filter='CSV files (*.csv)|*.csv|All files (*.*)|*.*'; required=$true },
                    @{ name='verifyOnly';          label='Verify only (dry run - check current state, change nothing)'; type='bool'; required=$false; default=$false },
                    @{ name='includeExperimental'; label='Include Experimental matches (MS Store / Defender check)'; type='bool'; required=$false; default=$false },
                    @{ name='preferSoftwareCenter';label='Prefer Software Center variant where available'; type='bool'; required=$false; default=$false },
                    @{ name='threads';             label='Parallel hosts'; type='int'; required=$false; default=20 }
                )
            },
            @{
                id          = 'run-vulnerability'
                label       = 'Run Vulnerability Update'
                description  = 'Push a single App Update profile to the host set affected by one vulnerability. TCP probe, bounded Negotiate PSSession (NetBIOS NTLM fallback), update + verify in one session.'
                kind         = 'stream-table'
                destructive  = $true
                columns      = @('Host','Result','Version Before','Version After','Mode','Timestamp','Detail')
                inputs       = @(
                    @{ name='profileName'; label='App Update profile'; type='text'; required=$true; default='Windows Defender - Update Definitions' },
                    @{ name='vulnDisplay'; label='Vulnerability name (for logging)'; type='text'; required=$false },
                    @{ name='targets';     label='Affected hosts (one per line)'; type='hostlist'; required=$true },
                    @{ name='verifyOnly';  label='Verify only (skip update)'; type='bool'; required=$false; default=$false },
                    @{ name='threads';     label='Parallel hosts'; type='int'; required=$false; default=20 }
                )
            },
            @{
                id          = 'run-all-sequential'
                label       = 'Run All (Sequential)'
                description  = 'Run a queue of (profile, host-set) jobs one profile at a time, draining each before the next. Same per-host engine as Run Vulnerability Update.'
                kind         = 'stream-table'
                destructive  = $true
                columns      = @('Host','Profile','Result','Version Before','Version After','Timestamp','Detail')
                inputs       = @(
                    @{ name='jobs';       label='Jobs: lines of  profile | host1,host2,...'; type='textarea'; required=$true },
                    @{ name='verifyOnly'; label='Verify only (skip update)'; type='bool'; required=$false; default=$false },
                    @{ name='threads';    label='Parallel hosts (within each profile)'; type='int'; required=$false; default=20 }
                )
            },
            @{
                id          = 'run-all-parallel'
                label       = 'Bulk Run (Parallel)'
                description  = 'Submit every (profile, host) tuple to the runspace pool at once. Single drain across the heterogeneous batch. Each job tracks its own profile context.'
                kind         = 'stream-table'
                destructive  = $true
                columns      = @('Host','Profile','Result','Version Before','Version After','Timestamp','Detail')
                inputs       = @(
                    @{ name='jobs';       label='Jobs: lines of  profile | host1,host2,...'; type='textarea'; required=$true },
                    @{ name='verifyOnly'; label='Verify only (skip update)'; type='bool'; required=$false; default=$false },
                    @{ name='threads';    label='Parallel hosts'; type='int'; required=$false; default=20 }
                )
            },
            @{
                id          = 'preflight-services'
                label       = 'Pre-Flight Services'
                description  = 'Ensure the three services remote patching depends on (winrm, Winmgmt, RemoteRegistry) are Running + Automatic on each target over RPC (TCP 135/445 probe first, fast-fail on dead hosts). Run this when hosts fail to connect before a patch or verify wave.'
                kind         = 'stream-table'
                destructive  = $true   # sets winrm/Winmgmt/RemoteRegistry to Running+Automatic on each target - a state change, so confirm first (parity with the desktop pre-flight prompt)
                columns      = @('Host','Changes Made','Result','Timestamp','Detail')
                inputs       = @(
                    @{ name='targets'; label='Target hosts (one per line)'; type='hostlist'; required=$true },
                    @{ name='threads'; label='Parallel hosts'; type='int'; required=$false; default=20 }
                )
            }
            @{
                id          = 'schedule-reboot'
                label       = 'Schedule Reboot'
                description  = 'Schedule a reboot (shutdown /r /t 300) on the affected hosts of a Reboot-category vulnerability, showing the user a save-your-work warning. Use for findings whose only remediation is a pending reboot.'
                kind         = 'stream-table'
                destructive  = $true
                columns      = @('Host','Result','Exit Code','Timestamp','Detail')
                inputs       = @(
                    @{ name='targets';     label='Affected hosts (one per line)'; type='hostlist'; required=$true },
                    @{ name='vulnDisplay'; label='Vulnerability name (for logging)'; type='text'; required=$false },
                    @{ name='warningText'; label='User warning message'; type='text'; required=$false; default='This workstation will reboot in 5 minutes for required security updates. Save your work now.' },
                    @{ name='threads';     label='Parallel hosts'; type='int'; required=$false; default=20 }
                )
            }
            @{
                id          = 'verify-post-reboot'
                label       = 'Verify Post-Reboot'
                description  = 'Confirm the affected hosts came back after a scheduled reboot: reachability, pending-reboot flag, and OS build. Read/check only - changes nothing. Waits up to 10 min per host.'
                kind         = 'stream-table'
                destructive  = $false
                columns      = @('Host','Reachable','RebootPending','OS Build','Result','Timestamp','Detail')
                inputs       = @(
                    @{ name='targets';     label='Affected hosts (one per line)'; type='hostlist'; required=$true },
                    @{ name='vulnDisplay'; label='Vulnerability name (for logging)'; type='text'; required=$false },
                    @{ name='threads';     label='Parallel hosts'; type='int'; required=$false; default=20 }
                )
            }
            @{
                id          = 'kb-scan-findings'
                label       = 'Scan KB Findings (from CSV)'
                description  = 'Parse the imported ACAS/Nessus CSV and extract the Windows KB rollups referenced in each finding (plugin name + solution text). One row per host x KB with severity / plugin / CVE - the operator checks which to install on the KB Installer tab. Read-only.'
                kind         = 'table'
                destructive  = $false
                columns      = @('Host','KB','Severity','Plugin','CVE')
                inputs       = @(
                    @{ name='csvPaths'; label='ACAS CSV file'; type='file'; filter='CSV files (*.csv)|*.csv|All files (*.*)|*.*'; required=$true }
                )
            }
            @{
                id          = 'kb-install'
                label       = 'Install KBs'
                description  = 'Group the checked KB findings by host and install per host. Method MECM: match each KB in CCM_SoftwareUpdate (ComplianceState=0) by ArticleID/Name then CCM_SoftwareUpdatesManager.InstallUpdates. Method UsoClient: trigger StartScan + StartInstall. Any KB not deployed in MECM falls back to an uploaded .msu copied to the host and run via wusa. Honors suppress-reboot.'
                kind         = 'stream-table'
                destructive  = $true
                confirm      = 'Install the selected KB(s) on the checked host(s)? Proceed?'
                columns      = @('Host','KBs','MECM','MSU','Skipped','Result','Detail')
                inputs       = @(
                    @{ name='pairs';    label='Host -> KBs: lines of  host | KB1,KB2,...'; type='textarea'; required=$true },
                    @{ name='method';   label='Method (MECM (CIM targeted) | UsoClient Trigger)'; type='text'; required=$false; default='MECM (CIM targeted)' },
                    @{ name='msu';      label='MSU fallback file (optional)'; type='file'; filter='MSU files (*.msu)|*.msu|All files (*.*)|*.*'; required=$false },
                    @{ name='noreboot'; label='Suppress auto-reboot'; type='bool'; required=$false; default=$true },
                    @{ name='threads';  label='Parallel hosts'; type='int'; required=$false; default=12 }
                )
            }
        )
    }
}

# -----------------------------------------------------------------------------
#  Helpers (lifted from the original tool).
# -----------------------------------------------------------------------------

function Get-AcasShortHost {
    # Normalize an ACAS-emitted hostname to short form (lifted from Get-NemShortHost).
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return '' }
    $n = $Name.Trim()
    if ($n -match '\\') { $n = ($n -split '\\')[-1] }
    if ($n -match ':\d+$') { $n = $n -replace ':\d+$', '' }   # drop a trailing :port from pasted "host:5985" / "ip:445"
    if ($n -match '^\d+(\.\d+){3}$') { return $n }
    if ($n -match '\.') { $n = ($n -split '\.', 2)[0] }
    return $n
}

function Test-AcasIsServer {
    # Return $true when hostname matches the msek-* server prefix (lifted from Test-NemIsServer).
    param([string]$HostName)
    if ([string]::IsNullOrWhiteSpace($HostName)) { return $false }
    $h = $HostName.Trim()
    if ($h -match '\\') { $h = ($h -split '\\')[-1] }
    return ($h -match '^msek-')
}

function ConvertTo-AcasHostList {
    # Split a pasted blob into clean, unique, short-form hostnames.
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return @() }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $out  = New-Object System.Collections.ArrayList
    foreach ($tok in ($Raw -split '[\r\n,;\t ]+')) {
        $h = Get-AcasShortHost ($tok.Trim())
        # Accept only a bare host/IPv4 token; drop UNC/URL/junk before any remote call.
        if ($h -and ($h -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$') -and $seen.Add($h)) { [void]$out.Add($h) }
    }
    return $out.ToArray()
}

# =============================================================================
#  REMEDIATION MATCHING ENGINE  (the "auto-patch anything you can patch after
#  import" core - lifted from the original tool's Get-NemProfileMatchTable +
#  Get-NemVulnGroups). Turns parsed ACAS findings into classified vulnerability
#  groups: each group carries its matched App Update profile(s) and the exact
#  host set it affects, so the controller can dispatch the right fix to the
#  right machines without an all-hosts fallback.
# =============================================================================

# -----------------------------------------------------------------------------
#  Keyword -> profile rules (lifted from Get-NemProfileMatchTable). First rule
#  whose keyword is a substring of the plugin name wins; Profiles[0] is the
#  default variant, later entries are alternates (EXE-direct vs Software
#  Center). Specific rules (Edge STIG, Unquoted, MSXML) sit ABOVE the generic
#  browser rules on purpose so they aren't swallowed by 'Edge'/'Office'.
# -----------------------------------------------------------------------------
function Get-AcasProfileMatchTable {
    return @(
        @{ Keywords=@('EDGE-00-000022','Importing of search engine settings'); Profiles=@('Edge STIG - Disable Search Engine Import') }
        @{ Keywords=@('Unquoted Service Path');                                Profiles=@('Windows Unquoted Service Path - Remediate') }
        @{ Keywords=@('MSXML','XML Parser','XML Core Services');               Profiles=@('MSXML 4.0 - Uninstall') }
        # Keywords are specific ('Microsoft Office', not bare 'Office') and each rule
        # carries an Exclude list so look-alikes don't mis-route to the wrong fix:
        # LibreOffice/OpenOffice/WPS -> NOT Microsoft 365; Edge WebView2/EdgeTransport
        # -> NOT Edge browser; Chrome Remote Desktop -> NOT Chrome.
        @{ Keywords=@('Microsoft Office','Microsoft 365','Office 365','Microsoft Excel','Microsoft Word','Microsoft PowerPoint','Microsoft Outlook','Microsoft Access','Microsoft Publisher'); Exclude=@('LibreOffice','OpenOffice','WPS Office'); Profiles=@('Microsoft 365 - Force Update','Microsoft 365 - Force Update (SYSTEM task)','Microsoft 365 - Update (User Visible)','Microsoft 365 - Software Center') }
        @{ Keywords=@('Google Chrome');     Exclude=@('Remote Desktop'); Profiles=@('Google Chrome - Update','Google Chrome - Software Center') }
        @{ Keywords=@('Microsoft Edge');    Exclude=@('WebView','EdgeTransport','EdgeUpdate'); Profiles=@('Microsoft Edge - Update','Microsoft Edge - Software Center') }
        @{ Keywords=@('Windows Defender','Microsoft Defender','Endpoint Protection'); Profiles=@('Windows Defender - Update Definitions') }
        @{ Keywords=@('Apache Log4j','Log4j');                                         Profiles=@('Apache Log4j - Replace Vulnerable Jars') }
        @{ Keywords=@('Tenable Nessus Agent','Nessus Agent','Tenable Nessus');         Profiles=@('Tenable Nessus Agent - Package Deploy') }
        @{ Keywords=@('Oracle Java','Oracle JRE','Java SE Multiple Vulnerabilities'); Profiles=@('Oracle Java - Software Center') }
    )
}

# -----------------------------------------------------------------------------
#  Is a matched profile actually runnable from the JANET TWO web host?
#  Package deploys (IsPackage) and Log4j (NeedsStaging) require the controller-
#  side Packages\ / staged-jar tree, which the web host does not carry. These
#  are surfaced as coverage gaps by auto-patch rather than dispatched to fail.
# -----------------------------------------------------------------------------
function Test-AcasProfileAutoRunnable {
    param([string]$ProfileName, [bool]$StagingReady = $false)
    $prof = $script:AcasUpdateProfiles[$ProfileName]
    if (-not $prof) { return $false }
    if ($prof -is [hashtable]) {
        if ($prof.ContainsKey('IsPackage')    -and [bool]$prof['IsPackage'])    { return $false }
        # NeedsStaging (Log4j jar replace) is runnable IFF the controller-side
        # staged jars resolved this run (server stages them into each session).
        if ($prof.ContainsKey('NeedsStaging') -and [bool]$prof['NeedsStaging']) { return [bool]$StagingReady }
        if (-not $prof['Script']) { return $false }
    }
    return $true
}

# -----------------------------------------------------------------------------
#  Resolve the controller-side Log4j staged-jar source. Default is the JANET TWO
#  host's own Packages\Log4j\NewFiles (operators grab the 2.25.4 jars from the
#  desktop staging share and drop them there); an operator override (UNC or local
#  folder) wins. "Ready" means both the api and core 2.25.4 jars are present where
#  the JANET TWO host can read them - the host then Copy-Item -ToSession's them
#  into each target session (no double-hop).
# -----------------------------------------------------------------------------
function Resolve-AcasLog4jSource {
    param([string]$Override = '')
    $local = Join-Path (Join-Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'Packages') 'Log4j') 'NewFiles'
    $share = '\\dm-tn-01\sh-usafe-automation$\JANET\Packages\Log4j\NewFiles'

    # True only when BOTH patched jars are present at $p. For a UNC path the server
    # is TCP-gated first (445, AFNET-safe, never ICMP) so an unreachable share fails
    # fast instead of blocking the whole dispatch on the SMB timeout.
    $hasJars = {
        param($p)
        if ([string]::IsNullOrWhiteSpace($p)) { return $false }
        try {
            if ($p -match '^\\\\([^\\]+)') {
                # AFNET-safe reachability: TCP 445 (SMB), never ICMP. An unreachable
                # share fast-fails here instead of blocking on the SMB timeout.
                $srv = $Matches[1]; $tcpOk = $false; $tc = $null
                try { $tc = New-Object System.Net.Sockets.TcpClient; $iar = $tc.BeginConnect($srv, 445, $null, $null); if ($iar.AsyncWaitHandle.WaitOne(1500, $false) -and $tc.Connected) { $tcpOk = $true } } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
                if (-not $tcpOk) { return $false }
            }
            return ((Test-Path -LiteralPath (Join-Path $p 'log4j-api-2.25.4.jar')) -and (Test-Path -LiteralPath (Join-Path $p 'log4j-core-2.25.4.jar')))
        } catch { return $false }
    }

    # Override wins; else the local staging folder; else AUTO-FIND by recursively
    # hunting the host's Packages tree for any folder holding BOTH 2.25.4 jars (the
    # operator may have dropped the package anywhere under it); else the work share;
    # else report the local default path.
    if (-not [string]::IsNullOrWhiteSpace($Override)) { $path = $Override.Trim().Trim('"') }
    elseif (& $hasJars $local) { $path = $local }
    else {
        $pkgRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'Packages'
        $autoDir = $null
        if (Test-Path -LiteralPath $pkgRoot) {
            try {
                foreach ($hit in @(Get-ChildItem -LiteralPath $pkgRoot -Filter 'log4j-api-2.25.4.jar' -Recurse -File -ErrorAction SilentlyContinue)) {
                    if (Test-Path -LiteralPath (Join-Path $hit.DirectoryName 'log4j-core-2.25.4.jar')) { $autoDir = $hit.DirectoryName; break }
                }
            } catch {}
        }
        if     ($autoDir)          { $path = $autoDir }
        elseif (& $hasJars $share) { $path = $share }
        else                       { $path = $local }
    }

    $ready = [bool](& $hasJars $path)
    return @{ Path=$path; Ready=$ready; Api=(Join-Path $path 'log4j-api-2.25.4.jar'); Core=(Join-Path $path 'log4j-core-2.25.4.jar') }
}

# -----------------------------------------------------------------------------
#  Shared CSV -> finding-object parser. Reads one or more ACAS/Nessus CSV
#  exports (and/or pasted CSV text), normalizes each row to a finding with a
#  resolved short Host (DNS > NetBIOS > IP), drops msek-* server rows, and
#  returns @{ Findings=@(...); RowCount=int; ServersSkipped=int }.
#  Each finding: @{ Host; PluginId; PluginName; Severity; Cve }.
# -----------------------------------------------------------------------------
function ConvertFrom-AcasCsv {
    param([string[]]$Paths, [string]$Text, [scriptblock]$Send)

    $allRows = New-Object System.Collections.ArrayList
    foreach ($path in @($Paths | Where-Object { $_ })) {
        $pp = ([string]$path).Trim().Trim('"')
        if (-not $pp) { continue }
        if (-not (Test-Path -LiteralPath $pp)) {
            if ($Send) { & $Send @{ type='log'; level='warn'; text="File not found: $pp" } }
            continue
        }
        try {
            # -Encoding UTF8 so UTF-8 exports (with or without BOM) decode correctly
            # regardless of the box's ANSI code page (ACAS/Nessus exports are UTF-8).
            foreach ($r in (Import-Csv -LiteralPath $pp -Encoding UTF8 -ErrorAction Stop)) { [void]$allRows.Add($r) }
        } catch {
            if ($Send) { & $Send @{ type='log'; level='err'; text="Failed to parse '$pp': $($_.Exception.Message)" } }
        }
    }
    if ($Text -and -not [string]::IsNullOrWhiteSpace($Text)) {
        try {
            foreach ($r in (ConvertFrom-Csv $Text)) { [void]$allRows.Add($r) }
        } catch {
            if ($Send) { & $Send @{ type='log'; level='err'; text="Failed to parse pasted CSV: $($_.Exception.Message)" } }
        }
    }

    $map = $script:AcasColumnMap
    $getCol = {
        param($row, $colName)
        if (-not $colName) { return '' }
        $p = $row.PSObject.Properties[$colName]
        if ($p) { return ([string]$p.Value).Trim() }
        return ''
    }

    $findings = New-Object System.Collections.ArrayList
    $serversSkipped = 0
    $noHostSkipped  = 0
    foreach ($r in $allRows) {
        $dns = Get-AcasShortHost (& $getCol $r $map.dnsName)
        $nb  = Get-AcasShortHost (& $getCol $r $map.netbios)
        $ip  = (& $getCol $r $map.ip)
        $pick = if ($dns) { $dns } elseif ($nb) { $nb } elseif ($ip) { $ip } else { '' }
        if (-not $pick) { $noHostSkipped++; continue }
        if (Test-AcasIsServer -HostName $pick) { $serversSkipped++; continue }
        [void]$findings.Add([pscustomobject]@{
            Host       = $pick
            PluginId   = (& $getCol $r $map.pluginId)
            PluginName = (& $getCol $r $map.pluginName)
            Severity   = (& $getCol $r $map.severity)
            Cve        = (& $getCol $r $map.cve)
            Solution   = (& $getCol $r $map.solution)
        })
    }
    # Loud hint when rows parsed but nothing mapped to a host - almost always a
    # column-header mismatch (wrong export template) rather than an empty scan.
    if ($Send -and $allRows.Count -gt 0 -and $findings.Count -eq 0 -and $noHostSkipped -eq $allRows.Count) {
        & $Send @{ type='log'; level='warn'; text="Parsed $($allRows.Count) row(s) but none had a DNS/NetBIOS/IP value - check the CSV column headers match the expected ACAS export (DNS Name / NetBIOS Name / IP Address)." }
    }
    return @{ Findings=@($findings); RowCount=$allRows.Count; ServersSkipped=$serversSkipped; NoHostSkipped=$noHostSkipped }
}

# -----------------------------------------------------------------------------
#  Classify + group findings by plugin (lifted from Get-NemVulnGroups). Each
#  group resolves: Category (Patchable / Experimental / Reboot / Unpatchable /
#  NotUpdatable), matched ProfileNames, affected Hosts, max Severity, CVEs.
#  Takes the parsed finding array directly (stateless - no global selection).
#  Returned sorted: Patchable first, then by severity desc, host count desc.
# -----------------------------------------------------------------------------
function Get-AcasVulnGroups {
    param([object[]]$Findings)
    if (-not $Findings -or $Findings.Count -eq 0) { return @() }

    $matchTable = Get-AcasProfileMatchTable
    $sevRank = @{ 'critical'=5; 'high'=4; 'medium'=3; 'low'=2; 'info'=1; 'informational'=1 }

    $classifyPlugin = {
        param([string]$PluginName)
        $unpatchPatterns = @('Oracle Database','Speculative Execution','Intel BHI','Spectre','Meltdown','ZombieLoad')
        foreach ($pat in $unpatchPatterns) {
            if ($PluginName.IndexOf($pat, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                return @{ Category='Unpatchable'; ProfileOverride=$null }
            }
        }
        # Negation guard: don't classify "no reboot required" / "without reboot" as Reboot.
        $rebootNegated = ($PluginName.IndexOf('no reboot',      [System.StringComparison]::OrdinalIgnoreCase) -ge 0) -or
                         ($PluginName.IndexOf('not required',   [System.StringComparison]::OrdinalIgnoreCase) -ge 0) -or
                         ($PluginName.IndexOf('without reboot',  [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
        $isRebootExplicit = ($PluginName.IndexOf('Windows Update Reboot Required', [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
        $isRebootGeneric  = (($PluginName.IndexOf('Reboot',   [System.StringComparison]::OrdinalIgnoreCase) -ge 0) -and
                             ($PluginName.IndexOf('Required', [System.StringComparison]::OrdinalIgnoreCase) -ge 0))
        if (-not $rebootNegated -and ($isRebootExplicit -or $isRebootGeneric)) { return @{ Category='Reboot'; ProfileOverride=$null } }

        $hasWindowsApp = ($PluginName.IndexOf('Windows App', [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
        $hasRce        = ($PluginName.IndexOf('RCE',         [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
        $hasCve        = ($PluginName.IndexOf('CVE-',        [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
        if ($hasWindowsApp -and ($hasRce -or $hasCve)) {
            return @{ Category='Experimental'; ProfileOverride=@('Microsoft Store - Update Apps') }
        }
        $hasDefender = ($PluginName.IndexOf('Defender', [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
        $hasCheck    = ($PluginName.IndexOf('Check',    [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
        $hasSigDef   = ($PluginName.IndexOf('Signature Definition', [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
        if ($hasDefender -and ($hasCheck -or $hasSigDef)) {
            return @{ Category='Experimental'; ProfileOverride=$null }
        }
        return @{ Category=$null; ProfileOverride=$null }
    }

    $groups = [ordered]@{}
    foreach ($row in $Findings) {
        $plugin = [string]$row.PluginName
        if ([string]::IsNullOrWhiteSpace($plugin)) { continue }
        $key = $plugin.ToLowerInvariant()

        if (-not $groups.Contains($key)) {
            $classResult     = & $classifyPlugin $plugin
            $forcedCategory  = $classResult.Category
            $profileOverride = $classResult.ProfileOverride

            $matchedList = @()
            if ($profileOverride -ne $null) {
                $matchedList = @($profileOverride)
            } elseif ($forcedCategory -ne 'Unpatchable' -and $forcedCategory -ne 'Reboot') {
                foreach ($rule in $matchTable) {
                    # negative guard: skip this rule if the plugin name contains a look-alike token
                    $excluded = $false
                    if ($rule.ContainsKey('Exclude')) {
                        foreach ($ex in $rule.Exclude) {
                            if ($plugin.IndexOf($ex, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $excluded = $true; break }
                        }
                    }
                    if ($excluded) { continue }
                    foreach ($kw in $rule.Keywords) {
                        if ($plugin.IndexOf($kw, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                            $matchedList = @($rule.Profiles); break
                        }
                    }
                    if ($matchedList.Count -gt 0) { break }
                }
            }

            $finalCategory = $forcedCategory
            if (-not $finalCategory) {
                if ($matchedList.Count -gt 0) { $finalCategory = 'Patchable' }
                else                          { $finalCategory = 'NotUpdatable' }
            }

            $groups[$key] = [pscustomobject]@{
                PluginKey    = $key
                DisplayName  = $plugin
                Severity     = ''
                Category     = $finalCategory
                ProfileNames = $matchedList
                Hosts        = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                Cves         = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                Solution     = ''
                _sevRank     = 0
            }
        }
        $g = $groups[$key]
        if ($row.Host) { [void]$g.Hosts.Add([string]$row.Host) }
        if ([string]::IsNullOrWhiteSpace([string]$g.Solution) -and -not [string]::IsNullOrWhiteSpace([string]$row.Solution)) { $g.Solution = [string]$row.Solution }

        $sev = [string]$row.Severity
        $rank = 0
        if ($sev) { $sk = $sev.ToLowerInvariant(); if ($sevRank.ContainsKey($sk)) { $rank = $sevRank[$sk] } }
        if ($rank -gt $g._sevRank) { $g._sevRank = $rank; $g.Severity = $sev }

        if ($row.Cve) {
            foreach ($c in ([string]$row.Cve -split '[,;\s]+')) { if ($c) { [void]$g.Cves.Add($c.Trim()) } }
        }
    }

    $catOrder = @{ 'Patchable'=0; 'Experimental'=1; 'Reboot'=2; 'Unpatchable'=3; 'NotUpdatable'=4 }
    $flat = New-Object System.Collections.ArrayList
    foreach ($key in $groups.Keys) {
        $g = $groups[$key]
        $catRank = 99
        if ($catOrder.ContainsKey($g.Category)) { $catRank = $catOrder[$g.Category] }
        [void]$flat.Add([pscustomobject]@{
            PluginKey    = $g.PluginKey
            DisplayName  = $g.DisplayName
            Severity     = $g.Severity
            Category     = $g.Category
            SevRank      = $g._sevRank
            CatRank      = $catRank
            ProfileNames = @($g.ProfileNames)
            Hosts        = @(@($g.Hosts) | Sort-Object)
            HostCount    = $g.Hosts.Count
            Cves         = @(@($g.Cves) | Sort-Object)
            Solution     = [string]$g.Solution
        })
    }
    return @($flat | Sort-Object -Property `
        @{Expression='CatRank';     Descending=$false}, `
        @{Expression='SevRank';     Descending=$true}, `
        @{Expression='HostCount';   Descending=$true}, `
        @{Expression='DisplayName'; Descending=$false})
}

# -----------------------------------------------------------------------------
#  Version helpers for rollup: pull the highest dotted version out of a plugin
#  name and pick the "latest model" member of a rolled-up group.
# -----------------------------------------------------------------------------
function Get-AcasMaxVersion {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    # Strip tokens that look like versions but aren't: CVE ids, KB numbers, years.
    $t = $Text
    $t = [regex]::Replace($t, '(?i)CVE-\d{4}-\d+', ' ')
    $t = [regex]::Replace($t, '(?i)KB\d+', ' ')
    $t = [regex]::Replace($t, '\b(?:19|20)\d{2}\b', ' ')
    # Prefer a version introduced by '<' / 'prior to' / 'before' / 'version' (the
    # "Product < X.Y.Z" form ACAS uses); fall back to any dotted token otherwise.
    $pool = New-Object System.Collections.ArrayList
    foreach ($m in [regex]::Matches($t, '(?i)(?:<|prior to|before|version|ver\.?)\s*v?(\d+(?:\.\d+){1,3})')) { [void]$pool.Add($m.Groups[1].Value) }
    if ($pool.Count -eq 0) {
        foreach ($m in [regex]::Matches($t, '\d+(?:\.\d+){1,3}')) { [void]$pool.Add($m.Value) }
    }
    $max = $null
    foreach ($vstr in $pool) {
        $v = $null
        if ([version]::TryParse($vstr, [ref]$v)) { if ($null -eq $max -or $v -gt $max) { $max = $v } }
    }
    return $max
}
function Get-AcasLatestMember {
    # Members: @( @{ Name; HostCount; Severity } ). Returns the one whose plugin
    # name carries the highest version ("latest model"); ties and no-version
    # families fall back to highest severity, then most hosts.
    param([object[]]$Members)
    $sevRank = @{ 'critical'=5; 'high'=4; 'medium'=3; 'low'=2; 'info'=1; 'informational'=1 }
    $rankOf  = { param($s) $k = ([string]$s).ToLowerInvariant(); if ($sevRank.ContainsKey($k)) { $sevRank[$k] } else { 0 } }
    $best = $null; $bestVer = $null
    foreach ($m in $Members) {
        $v = Get-AcasMaxVersion $m.Name
        if ($null -eq $v) { continue }
        if ($null -eq $bestVer -or $v -gt $bestVer) { $bestVer = $v; $best = $m }
        elseif ($v -eq $bestVer) {
            $rm = & $rankOf $m.Severity; $rb = & $rankOf $best.Severity
            if ($rm -gt $rb -or ($rm -eq $rb -and [int]$m.HostCount -gt [int]$best.HostCount)) { $best = $m }
        }
    }
    if ($best) { return $best }
    return (@($Members | Sort-Object @{Expression={ & $rankOf $_.Severity }; Descending=$true}, @{Expression={ [int]$_.HostCount }; Descending=$true})[0])
}

# -----------------------------------------------------------------------------
#  Remediation rollup (mirrors the desktop tool's Get-NemVulnCardEntries): fuse
#  every Patchable/Experimental plugin that routes to the SAME remediation
#  profile set into ONE card -- e.g. all "Google Chrome < X" plugins and all
#  Office/365 plugins collapse to a single Chrome / 365 card, titled with the
#  LATEST version and covering the UNION of affected hosts. Reboot / Unpatchable
#  / NotUpdatable (and any no-profile) groups stay as individual cards.
#  Deterministic, so analyze (cards) and patch-selected (dispatch) agree on Key.
# -----------------------------------------------------------------------------
function Get-AcasRemediationGroups {
    param([object[]]$Findings)
    $base = @(Get-AcasVulnGroups -Findings $Findings)
    if ($base.Count -eq 0) { return @() }

    $rolled = [ordered]@{}
    foreach ($g in $base) {
        $rollable = (($g.Category -eq 'Patchable' -or $g.Category -eq 'Experimental') -and $g.ProfileNames.Count -gt 0)
        if ($rollable) {
            $sig = (((@($g.ProfileNames) | Sort-Object) -join '||')).ToLowerInvariant()
            $key = 'sig:' + $g.Category.ToLowerInvariant() + '|' + $sig
        } else {
            $key = 'plg:' + $g.PluginKey
        }
        if (-not $rolled.Contains($key)) {
            $rolled[$key] = [pscustomobject]@{
                Key          = $key
                Category     = $g.Category
                ProfileNames = @($g.ProfileNames)
                Hosts        = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                Cves         = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                Members      = New-Object System.Collections.ArrayList
                Severity     = ''
                Solution     = ''
                _sevRank     = 0
            }
        }
        $r = $rolled[$key]
        foreach ($h in $g.Hosts) { [void]$r.Hosts.Add($h) }
        foreach ($c in $g.Cves)  { [void]$r.Cves.Add($c) }
        if ([string]::IsNullOrWhiteSpace([string]$r.Solution) -and -not [string]::IsNullOrWhiteSpace([string]$g.Solution)) { $r.Solution = [string]$g.Solution }
        [void]$r.Members.Add([pscustomobject]@{ Name=$g.DisplayName; HostCount=$g.HostCount; Severity=$g.Severity })
        if ($g.SevRank -gt $r._sevRank) { $r._sevRank = $g.SevRank; $r.Severity = $g.Severity }
    }

    $catOrder = @{ 'Patchable'=0; 'Experimental'=1; 'Reboot'=2; 'Unpatchable'=3; 'NotUpdatable'=4 }
    $flat = New-Object System.Collections.ArrayList
    foreach ($key in $rolled.Keys) {
        $r = $rolled[$key]
        $latest = Get-AcasLatestMember -Members @($r.Members)
        $catRank = if ($catOrder.ContainsKey($r.Category)) { $catOrder[$r.Category] } else { 99 }
        [void]$flat.Add([pscustomobject]@{
            Key          = $r.Key
            DisplayName  = $latest.Name
            MemberCount  = $r.Members.Count
            MemberNames  = @(@($r.Members | ForEach-Object { $_.Name }) | Sort-Object -Unique)
            Category     = $r.Category
            Severity     = $r.Severity
            SevRank      = $r._sevRank
            CatRank      = $catRank
            ProfileNames = @($r.ProfileNames)
            Hosts        = @(@($r.Hosts) | Sort-Object)
            HostCount    = $r.Hosts.Count
            Cves         = @(@($r.Cves) | Sort-Object)
            Solution     = [string]$r.Solution
        })
    }
    return @($flat | Sort-Object -Property `
        @{Expression='CatRank';     Descending=$false}, `
        @{Expression='SevRank';     Descending=$true}, `
        @{Expression='HostCount';   Descending=$true}, `
        @{Expression='DisplayName'; Descending=$false})
}

# -----------------------------------------------------------------------------
#  Per-host UPDATE worker (lifted verbatim from Start-NemVulnRun's inline
#  scriptblock: TCP probe, bounded Negotiate PSSession with NetBIOS fallback,
#  verify-before/update/verify-after in one session via combined rehydration).
#  IsPackage profiles return a structured FAIL (no controller Packages\ tree
#  in the web host). Returns a string: "OK*"/"FAIL*"/"SKIP*".
# -----------------------------------------------------------------------------
$script:AcasUpdateWorker = {
    param($TargetIn, $ProfileIn, $UpdateProfilesTable, $VerifyOnlyIn, $CredIn, $StageSource)
    $prof = $UpdateProfilesTable[$ProfileIn]
    if (-not $prof) { return "FAIL: Unknown profile '$ProfileIn'." }

    # IsPackage profiles need the controller-side Packages\ staging tree, which
    # the web host does not carry. Fail structured rather than half-deploy.
    $isPkgProfile = $false; $needsStaging = $false
    try {
        if ($prof -is [hashtable] -and $prof.ContainsKey('IsPackage')) { $isPkgProfile = [bool]$prof['IsPackage'] }
        elseif ($prof.PSObject -and $prof.PSObject.Properties['IsPackage']) { $isPkgProfile = [bool]$prof.IsPackage }
        if ($prof -is [hashtable] -and $prof.ContainsKey('NeedsStaging')) { $needsStaging = [bool]$prof['NeedsStaging'] }
        elseif ($prof.PSObject -and $prof.PSObject.Properties['NeedsStaging']) { $needsStaging = [bool]$prof.NeedsStaging }
    } catch {}
    if ($isPkgProfile -and -not $VerifyOnlyIn) {
        return "FAIL: package-deploy profile not supported in JANET TWO host (no controller Packages\ staging tree)."
    }
    # NeedsStaging (Log4j) full-run requires a resolved controller-side jar source;
    # the host copies the jars into the session below (no remote double-hop).
    if ($needsStaging -and -not $VerifyOnlyIn -and [string]::IsNullOrWhiteSpace([string]$StageSource)) {
        return "FAIL: Log4j staging source not available (drop log4j-api/core-2.25.4.jar where the JANET TWO host can read them, or set a staging path)."
    }

    # Inline TCP reachability probe (5985 then 445, 3s each).
    $reachable = $false
    foreach ($port in 5985, 445) {
        $tc = $null
        try {
            $tc  = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($TargetIn, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(3000, $false) -and $tc.Connected) { $reachable = $true }
        } catch {}
        finally { if ($tc) { try { $tc.Close() } catch {} } }
        if ($reachable) { break }
    }
    if (-not $reachable) { return "FAIL: unreachable (TCP 5985/445)" }

    $wsOpt = New-PSSessionOption -OperationTimeout 180000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
    $sessArgs = @{
        ComputerName   = $TargetIn
        SessionOption  = $wsOpt
        Authentication = 'Negotiate'
        ErrorAction    = 'Stop'
    }
    if ($CredIn) { $sessArgs['Credential'] = $CredIn }
    $sess = $null
    try { $sess = New-PSSession @sessArgs }
    catch {
        $sessErr = $_.Exception.Message
        # NetBIOS NTLM fallback on Negotiate/SPN failures.
        if ($TargetIn -match '\.' -and (
                $sessErr -match '0x80090322' -or
                $sessErr -match 'Negotiate authentication' -or
                $sessErr -match 'Access is denied'
            )) {
            $nbName = ($TargetIn -split '\.')[0]
            $sessArgs2 = @{} + $sessArgs
            $sessArgs2['ComputerName'] = $nbName
            try {
                $sess = New-PSSession @sessArgs2
            } catch {
                return "FAIL: Session - $sessErr (NetBIOS retry [$nbName] also failed: $($_.Exception.Message))"
            }
        } else {
            return "FAIL: Session - $sessErr"
        }
    }

    try {
        if ($VerifyOnlyIn) {
            if (-not $prof.Verify) { return 'SKIP: profile has no Verify block' }
            try {
                $out = Invoke-Command -Session $sess -ScriptBlock $prof.Verify -ErrorAction Stop
                if ($out -is [hashtable]) {
                    $ver  = if ($out.Version)     { [string]$out.Version }     else { 'unknown' }
                    $last = if ($out.LastUpdated) { [string]$out.LastUpdated } else { 'n/a' }
                    $ver2 = $out.Verified
                    $flag = if ($ver2 -eq $true) { 'fresh' } elseif ($null -eq $ver2) { 'n/a' } else { 'stale' }
                    $detail = if ($out.Detail) { " ($([string]$out.Detail))" } else { '' }
                    return "v=$ver last=$last [$flag]$detail"
                }
                if ($null -eq $out) { return 'OK (no output)' }
                return [string]$out
            } catch {
                return "FAIL: $($_.Exception.Message)"
            }
        }

        # Full update: verify-before, update, verify-after in ONE session.
        # Scriptblocks do not round-trip over WinRM -ArgumentList, so we pass
        # the source text and rehydrate with [scriptblock]::Create() remotely.
        $updateText = [string]$prof.Script.ToString()
        $verifyText = if ($prof.Verify) { [string]$prof.Verify.ToString() } else { '' }

        # Log4j (NeedsStaging): copy the controller-side jars INTO this session's
        # per-host temp (Copy-Item -ToSession - no remote second hop to the UNC),
        # then rewrite the Script's $sourceShare to that local temp before running.
        if ($needsStaging) {
            $remoteTemp = 'C:\Windows\Temp\JanetLog4j'
            # TCP-gate a UNC staging source so an unreachable share fast-fails instead
            # of hanging this pool slot on the SMB timeout (run-vulnerability/run-all
            # pass the path even when readiness wasn't pre-checked).
            if ($StageSource -match '^\\\\([^\\]+)') {
                # AFNET-safe reachability: TCP 445 (SMB), never ICMP.
                $stgSrv = $Matches[1]; $stgOk = $false; $stgTc = $null
                try { $stgTc = New-Object System.Net.Sockets.TcpClient; $stgIar = $stgTc.BeginConnect($stgSrv, 445, $null, $null); if ($stgIar.AsyncWaitHandle.WaitOne(1500, $false) -and $stgTc.Connected) { $stgOk = $true } } catch {} finally { if ($stgTc) { try { $stgTc.Close() } catch {} } }
                if (-not $stgOk) { return "FAIL: Log4j staging source unreachable ($StageSource)" }
            }
            try {
                Invoke-Command -Session $sess -ErrorAction Stop -ArgumentList $remoteTemp -ScriptBlock {
                    param($d)
                    if (Test-Path -LiteralPath $d) { Get-ChildItem -LiteralPath $d -Filter 'log4j-*.jar' -EA SilentlyContinue | Remove-Item -Force -EA SilentlyContinue }
                    else { New-Item -ItemType Directory -Path $d -Force | Out-Null }
                } | Out-Null
                $srcJars = @(Get-ChildItem -LiteralPath $StageSource -Filter 'log4j-*.jar' -File -ErrorAction Stop)
                if ($srcJars.Count -eq 0) { return "FAIL: no log4j-*.jar at staging source '$StageSource'" }
                foreach ($j in $srcJars) { Copy-Item -LiteralPath $j.FullName -Destination $remoteTemp -ToSession $sess -Force -ErrorAction Stop }
            } catch { return "FAIL: Log4j staging failed: $($_.Exception.Message)" }
            $updateText = [regex]::Replace($updateText, "\`$sourceShare\s*=\s*'[^']*'", { param($m) "`$sourceShare = '$remoteTemp'" })
        }
        $combined = {
            param($updateTxt, $verifyTxt)
            $pre = $null
            if ($verifyTxt) {
                try { $pre = & ([scriptblock]::Create($verifyTxt)) } catch { $pre = $null }
            }

            $updateOut = & ([scriptblock]::Create($updateTxt))
            $updateStr = if ($null -eq $updateOut) { 'OK (no output)' } else { [string]$updateOut }

            $post = $null
            if ($verifyTxt) {
                try { $post = & ([scriptblock]::Create($verifyTxt)) } catch { $post = $null }
            }

            return @{ Update = $updateStr; Pre = $pre; Post = $post }
        }
        try {
            $result = Invoke-Command -Session $sess -ScriptBlock $combined `
                                     -ArgumentList $updateText, $verifyText `
                                     -ErrorAction Stop
            $updateStr = [string]$result.Update
            $preV  = if ($result.Pre  -is [hashtable] -and $result.Pre.Version)  { [string]$result.Pre.Version }  else { 'n/a' }
            $postV = if ($result.Post -is [hashtable] -and $result.Post.Version) { [string]$result.Post.Version } else { 'n/a' }
            $marker = "<<PRE=$preV>><<POST=$postV>>"
            if ($preV -eq 'n/a' -and $postV -eq 'n/a') { return "$updateStr $marker" }
            $diff = if ($preV -eq $postV) { 'unchanged (async update may be in progress)' } else { "bumped: $preV -> $postV" }
            return "$updateStr | $diff $marker"
        } catch {
            return "FAIL: $($_.Exception.Message)"
        }
    } finally {
        if ($sess) { try { Remove-PSSession $sess -ErrorAction SilentlyContinue } catch {} }
    }
}

# -----------------------------------------------------------------------------
#  Per-host REBOOT worker (lifted from Start-NemRebootRun's scriptblock).
#  shutdown.exe runs locally on the controller targeting \\HOST.
# -----------------------------------------------------------------------------
$script:AcasRebootWorker = {
    param($Target, $WarnMsg, $Cred)
    $shutdown = "$env:WinDir\System32\shutdown.exe"
    # Sanitize + bound operator free-text before it reaches shutdown.exe /c:
    # PS 5.1 array-join quoting can break argument boundaries on embedded
    # double-quotes/newlines, and shutdown.exe truncates /c past ~512 chars.
    $warn = [string]$WarnMsg
    $warn = $warn -replace '[\r\n"]', ' '
    if ($warn.Length -gt 500) { $warn = $warn.Substring(0, 500) }

    # Honor an operator-supplied Set-Credentials value: schedule the reboot in a
    # Negotiate session ON the target (shutdown.exe /r runs locally there) so the
    # operator's identity is used - not the server process's ambient token. Only
    # fall back to the ambient "/m \\HOST" path when no credential is set.
    if ($Cred) {
        try {
            $rc = Invoke-Command -ComputerName $Target -Authentication Negotiate -Credential $Cred `
                                 -ArgumentList $warn -ErrorAction Stop -ScriptBlock {
                param($w)
                & "$env:WinDir\System32\shutdown.exe" /r /t 300 /c $w | Out-Null
                $LASTEXITCODE
            }
            $rc = [int]$rc
            $who = [string]$Cred.UserName
            if ($rc -eq 0)        { return "OK (reboot scheduled via credential [$who], 300s warning) <<EXIT=0>>" }
            elseif ($rc -eq 1190) { return "OK (already scheduled via credential [$who], rc=1190) <<EXIT=1190>>" }
            else { return "FAIL: shutdown.exe exit code $rc (credential [$who]) <<EXIT=$rc>>" }
        } catch {
            return "FAIL: $($_.Exception.Message) (credential [$([string]$Cred.UserName)]) <<EXIT=>>"
        }
    }

    $shutArgs = @('/m', "\\$Target", '/r', '/t', '300', '/c', $warn)
    try {
        $proc = Start-Process -FilePath $shutdown -ArgumentList $shutArgs -Wait -PassThru -NoNewWindow
        if ($proc.ExitCode -eq 0)        { return "OK (reboot scheduled [ambient token], 300s warning) <<EXIT=0>>" }
        elseif ($proc.ExitCode -eq 1190) { return "OK (already scheduled [ambient token], rc=1190) <<EXIT=1190>>" }
        else { return "FAIL: shutdown.exe exit code $($proc.ExitCode) [ambient token] <<EXIT=$($proc.ExitCode)>>" }
    } catch {
        return "FAIL: $($_.Exception.Message) [ambient token] <<EXIT=>>"
    }
}

# -----------------------------------------------------------------------------
#  Per-host REBOOT-VERIFY worker (lifted from Start-NemRebootVerify's
#  scriptblock: TCP poll up to 10min, then PSSession reboot-pending + build).
# -----------------------------------------------------------------------------
$script:AcasRebootVerifyWorker = {
    param($TargetIn, $CredIn)

    $deadline = (Get-Date).AddMinutes(10)
    $reachable = $false
    while ((Get-Date) -lt $deadline) {
        foreach ($port in 5985, 445) {
            $tc = $null
            try {
                $tc  = New-Object System.Net.Sockets.TcpClient
                $iar = $tc.BeginConnect($TargetIn, $port, $null, $null)
                if ($iar.AsyncWaitHandle.WaitOne(3000, $false) -and $tc.Connected) { $reachable = $true }
            } catch {}
            finally { if ($tc) { try { $tc.Close() } catch {} } }
            if ($reachable) { break }
        }
        if ($reachable) { break }
        Start-Sleep -Seconds 15
    }

    if (-not $reachable) {
        return "FAIL: UNREACHABLE after 10min wait (TCP 5985/445 - still rebooting or offline) <<REACH=No>><<PENDING=?>><<BUILD=?>>"
    }

    $wsOpt = New-PSSessionOption -OperationTimeout 180000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
    $sessArgs = @{
        ComputerName   = $TargetIn
        SessionOption  = $wsOpt
        Authentication = 'Negotiate'
        ErrorAction    = 'Stop'
    }
    if ($CredIn) { $sessArgs['Credential'] = $CredIn }
    $sess = $null
    try { $sess = New-PSSession @sessArgs }
    catch {
        $sessErr = $_.Exception.Message
        if ($TargetIn -match '\.' -and (
                $sessErr -match '0x80090322' -or
                $sessErr -match 'Negotiate authentication' -or
                $sessErr -match 'Access is denied'
            )) {
            $nbName = ($TargetIn -split '\.')[0]
            $sessArgs2 = @{} + $sessArgs
            $sessArgs2['ComputerName'] = $nbName
            try {
                $sess = New-PSSession @sessArgs2
            } catch {
                return "FAIL: Session - $sessErr (NetBIOS retry [$nbName] also failed: $($_.Exception.Message)) <<REACH=Yes>><<PENDING=?>><<BUILD=?>>"
            }
        } else {
            return "FAIL: Session - $sessErr <<REACH=Yes>><<PENDING=?>><<BUILD=?>>"
        }
    }

    try {
        $result = Invoke-Command -Session $sess -ErrorAction Stop -ScriptBlock {
            $pendingPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
            $stillPending = Test-Path -Path $pendingPath

            $ntKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
            $ntProps = Get-ItemProperty -Path $ntKey -ErrorAction SilentlyContinue
            $build = if ($ntProps -and $ntProps.CurrentBuildNumber) { [string]$ntProps.CurrentBuildNumber } else { 'unknown' }
            $ubr   = if ($ntProps -and $ntProps.UBR)               { [string]$ntProps.UBR }               else { '0' }
            $disp  = if ($ntProps -and $ntProps.DisplayVersion)    { [string]$ntProps.DisplayVersion }    else { '' }

            return @{ StillPending = $stillPending; Build = $build; UBR = $ubr; DisplayVersion = $disp }
        }

        $buildStr = "$($result.Build).$($result.UBR)"
        # Friendly Windows release label: live registry DisplayVersion first, then a
        # static build->release map (a backstop that ages as new builds ship), then
        # Unknown. Surfaced in the 'OS Build' column so 22621.4317 reads as 22H2.
        $relMap = @{ '19041'='20H1'; '19042'='20H2'; '19043'='21H1'; '19044'='21H2'; '19045'='22H2'; '22000'='Win11 21H2'; '22621'='Win11 22H2'; '22631'='Win11 23H2'; '26100'='Win11 24H2'; '26200'='Win11 25H2' }
        $rel = if ($result.DisplayVersion) { [string]$result.DisplayVersion } elseif ($relMap.ContainsKey([string]$result.Build)) { $relMap[[string]$result.Build] } else { 'Unknown' }
        $buildLabel = "$buildStr ($rel)"
        if ($result.StillPending) {
            return "FAIL: still pending reboot (Build=$buildLabel) <<REACH=Yes>><<PENDING=Yes>><<BUILD=$buildLabel>>"
        }
        return "OK (Build=$buildLabel, RebootPending=false) <<REACH=Yes>><<PENDING=No>><<BUILD=$buildLabel>>"
    } catch {
        return "FAIL: $($_.Exception.Message) <<REACH=Yes>><<PENDING=?>><<BUILD=?>>"
    } finally {
        if ($sess) { try { Remove-PSSession $sess -ErrorAction SilentlyContinue } catch {} }
    }
}

# -----------------------------------------------------------------------------
#  Per-host PRE-FLIGHT SERVICES worker (lifted from Start-NemServicesPreflight).
#  winrm / Winmgmt / RemoteRegistry -> Running + Automatic.
# -----------------------------------------------------------------------------
$script:AcasPreflightWorker = {
    param($Target, $Cred, $Auth)
    # WinRM-only transport (AFNET-safe), credential-honoring: probe 5985/445 (3s
    # each) to fail a dead host fast, then open a Negotiate PSSession under the
    # OPERATOR credential and start/repair the services LOCALLY via Invoke-Command.
    # We never call Get-Service/Set-Service -ComputerName: that drives the SCM over
    # RPC (TCP 135 + dynamic high ports) and runs as the host's own service-account
    # identity - both disallowed here (mirrors every other worker in this file).
    $reachable = $false
    foreach ($port in 5985, 445) {
        $tc = $null
        try {
            $tc  = New-Object System.Net.Sockets.TcpClient
            $iar = $tc.BeginConnect($Target, $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(3000, $false) -and $tc.Connected) { $reachable = $true }
        } catch {}
        finally { if ($tc) { try { $tc.Close() } catch {} } }
        if ($reachable) { break }
    }
    if (-not $reachable) { return 'FAIL: unreachable (TCP 5985/445) <<CHANGES=>>' }

    $wsOpt = New-PSSessionOption -OperationTimeout 180000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 60000
    $sessArgs = @{
        ComputerName   = $Target
        SessionOption  = $wsOpt
        Authentication = $(if ($Auth) { $Auth } else { 'Negotiate' })
        ErrorAction    = 'Stop'
    }
    if ($Cred) { $sessArgs['Credential'] = $Cred }
    $sess = $null
    try { $sess = New-PSSession @sessArgs }
    catch {
        $sessErr = $_.Exception.Message
        # NetBIOS NTLM fallback on Negotiate/SPN failures.
        if ($Target -match '\.' -and (
                $sessErr -match '0x80090322' -or
                $sessErr -match 'Negotiate authentication' -or
                $sessErr -match 'Access is denied'
            )) {
            $nbName = ($Target -split '\.')[0]
            $sessArgs2 = @{} + $sessArgs
            $sessArgs2['ComputerName'] = $nbName
            try { $sess = New-PSSession @sessArgs2 }
            catch { return "FAIL: Session - $sessErr (NetBIOS retry [$nbName] also failed: $($_.Exception.Message)) <<CHANGES=>>" }
        } else {
            return "FAIL: Session - $sessErr <<CHANGES=>>"
        }
    }

    try {
        # Build the marker result string INSIDE the session (where the service
        # counts are unambiguous) and return it as a plain string - avoids any
        # empty-array-vs-$null deserialization quirk on the way back.
        $svcOut = Invoke-Command -Session $sess -ErrorAction Stop -ScriptBlock {
            $names   = @('winrm', 'Winmgmt', 'RemoteRegistry')
            $changes = @()
            $errs    = @()
            foreach ($n in $names) {
                try {
                    $svc = Get-Service -Name $n -ErrorAction Stop
                    $needStart = $svc.Status    -ne 'Running'
                    $needAuto  = $svc.StartType -ne 'Automatic'
                    if ($needStart -or $needAuto) {
                        [void](Set-Service -Name $n -StartupType Automatic -Status Running -PassThru -ErrorAction Stop)
                        $changes += $n
                    }
                } catch {
                    $errs += "$n ($($_.Exception.Message))"
                }
            }
            if ($errs.Count    -gt 0) { return 'FAIL: ' + ($errs    -join '; ') + " <<CHANGES=$($changes -join ',')>>" }
            if ($changes.Count -gt 0) { return 'OK (fixed: ' + ($changes -join ', ') + ")" + " <<CHANGES=$($changes -join ',')>>" }
            return 'OK (all three already Running + Automatic) <<CHANGES=>>'
        }
        return [string]$svcOut
    } catch {
        return "FAIL: $($_.Exception.Message) <<CHANGES=>>"
    } finally {
        if ($sess) { try { Remove-PSSession $sess -ErrorAction SilentlyContinue } catch {} }
    }
}

# -----------------------------------------------------------------------------
#  Module-level scriptblock constants (shared across switch arms).
# -----------------------------------------------------------------------------

# $script:AcasOkOf  -- success predicate shared by every fan-out call
$script:AcasOkOf = { param($res) (-not ($res -like 'FAIL*')) }

# $script:AcasUpdateRowOf -- 8-col update row (patch-selected/auto-patch/run-all)
#   $stamp is inlined so this is closure-free at module scope.
$script:AcasUpdateRowOf = {
    param($res, $hostName, $ctx)
    $pre  = Get-AcasMarker $res 'PRE'
    $post = Get-AcasMarker $res 'POST'
    @{
        Host             = $hostName
        Profile          = $ctx.Profile
        Result           = $(if ($res -like 'FAIL*') { 'FAIL' } elseif ($res -like 'SKIP*') { 'SKIP' } else { 'OK' })
        'Version Before' = $(if ($pre)  { $pre }  else { 'n/a' })
        'Version After'  = $(if ($post) { $post } else { 'n/a' })
        Timestamp        = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Detail           = (Remove-AcasMarkers $res)
    }
}

# $script:AcasDetOfProfile -- audit detail with profile prefix
$script:AcasDetOfProfile = { param($res, $hostName, $ctx) "$($ctx.Profile): $(Remove-AcasMarkers $res)" }

# $script:AcasDetOfPlain   -- audit detail, marker-stripped only
$script:AcasDetOfPlain   = { param($res, $hostName, $ctx) (Remove-AcasMarkers $res) }

# -----------------------------------------------------------------------------
#  Result-string parsers: pull the embedded <<...>> markers and strip them
#  back out of the human-readable detail.
# -----------------------------------------------------------------------------
function Get-AcasMarker {
    param([string]$Text, [string]$Key)
    if (-not $Text) { return '' }
    $m = [regex]::Match($Text, "<<$Key=([^>]*)>>")
    if ($m.Success) { return $m.Groups[1].Value }
    return ''
}
function Remove-AcasMarkers {
    param([string]$Text)
    if (-not $Text) { return '' }
    return ([regex]::Replace($Text, '\s*<<[A-Z]+=[^>]*>>', '')).Trim()
}

# -----------------------------------------------------------------------------
#  Shared runspace-pool fan-out (mirrors the reference module's harvest loop).
#  $Jobs is an array of @{ Host=..; Args=@(...); Context=@{...} }. $Work is the
#  per-host scriptblock. $RowOf builds the streamed row from (resultString,
#  hostName, context). $OkOf returns $true for a success result.
# -----------------------------------------------------------------------------
function Invoke-AcasFanOut {
    param(
        [object[]]$Jobs,
        [scriptblock]$Work,
        [int]$Threads,
        [scriptblock]$RowOf,
        [scriptblock]$OkOf,
        [string]$AuditAction,        # 'TouchHost' or 'VulnPatched'
        [scriptblock]$AuditDetailOf,
        [scriptblock]$Send,
        [scriptblock]$CancelCheck,   # returns $true when the operator pressed Cancel
        [int]$DeadlineSeconds = 0,   # wall-clock backstop; <=0 = scale to the work (see below)
        [int]$PerHostSeconds = 0,    # per-host limit; >0 abandons ONLY a host that overruns its OWN run clock (0 = off)
        # Run-telemetry: when -RunAction is set, emit one type='run' event at
        # completion (the server routes it to the daily ACAS-Nemesis-Runs CSV,
        # faithful to the desktop Write-NemRunSummary). For a rolled-up card pass
        # -RunGroupKey + -RunGroupMembers to fan out one Runs row per member vuln.
        [string]$RunAction = '',
        [string]$RunScope = '',
        [string]$RunProfile = '',
        [string]$RunMode = '',
        [string]$RunGroupKey = '',
        [string[]]$RunGroupMembers = @()
    )

    $runStart = Get-Date
    $iss  = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Threads, $iss, $Host)
    $pool.Open()

    $psJobs = New-Object System.Collections.ArrayList
    foreach ($j in $Jobs) {
        $ps = [powershell]::Create(); $ps.RunspacePool = $pool
        [void]$ps.AddScript($Work)
        foreach ($a in $j.Args) { [void]$ps.AddArgument($a) }
        [void]$psJobs.Add([pscustomobject]@{ Host=$j.Host; Context=$j.Context; PS=$ps; Async=$ps.BeginInvoke(); StartedAt=$null })
    }

    $rows = New-Object System.Collections.ArrayList
    $done = 0; $okCount = 0; $failCount = 0; $skipCount = 0
    # No explicit deadline from the caller: scale the backstop to the work instead
    # of a flat ceiling - the slowest workers legitimately run ~10 min/host
    # (reboot-verify TCP wait, M365 SYSTEM-task 600s poll), so allow one worst-case
    # worker per serialized wave plus fixed slack.
    if ($DeadlineSeconds -le 0) {
        $waves = [int][Math]::Ceiling($psJobs.Count / [double][Math]::Max(1, $Threads))
        $DeadlineSeconds = ($waves * 660) + 300
    }
    $deadline  = (Get-Date).AddSeconds([Math]::Max(60, $DeadlineSeconds))
    $cancelled = $false; $timedOut = $false
    try {
        while ($done -lt $psJobs.Count) {
            foreach ($pj in $psJobs) {
                # Stamp the real execution start: the pool queues anything beyond
                # $Threads, so a per-host clock from BeginInvoke would punish queued
                # hosts for slot-wait. NotStarted -> Running means a runspace took it.
                if ($pj.PS -and -not $pj.StartedAt -and $pj.PS.InvocationStateInfo.State -eq 'Running') { $pj.StartedAt = Get-Date }
                if ($pj.PS -and $pj.Async.IsCompleted) {
                    $resStr = ''
                    try {
                        $out = $pj.PS.EndInvoke($pj.Async)
                        if ($out -and @($out).Count -gt 0) { $resStr = [string]$out[0] }
                        else { $resStr = 'OK (no output)' }
                    } catch {
                        $resStr = "FAIL: worker error: $($_.Exception.Message)"
                    }
                    try { $pj.PS.Dispose() } catch {}
                    $pj.PS = $null

                    # Three-way classify so a no-op (SKIP) is never audited as a patch.
                    $isSkip = ($resStr -like 'SKIP*')
                    $ok = [bool](& $OkOf $resStr)
                    if     ($isSkip) { $skipCount++ }
                    elseif ($ok)     { $okCount++ }
                    else             { $failCount++ }

                    $row = & $RowOf $resStr $pj.Host $pj.Context
                    [void]$rows.Add($row)
                    & $Send (@{ type='row' } + $row)

                    $detail = [string](& $AuditDetailOf $resStr $pj.Host $pj.Context)
                    if ($detail.Length -gt 160) { $detail = $detail.Substring(0,160) }
                    $auditResult = if ($isSkip) { 'Skipped' } elseif ($ok) { 'Success' } else { 'Failure' }
                    $auditCount  = if ($isSkip -or -not $ok) { 0 } else { 1 }
                    & $Send @{ type='audit'; action=$AuditAction; target=$pj.Host;
                               result=$auditResult; itemCount=$auditCount; detail=$detail }

                    $done++
                    & $Send @{ type='progress'; done=$done; total=$psJobs.Count }
                }
            }
            # Per-host timeout: abandon ONLY the host(s) that overran their own run
            # clock so one hung host can't pin the whole wave (the batch deadline
            # below is the all-or-nothing ceiling; this is the surgical one). Mirrors
            # the batch abandon - BeginStop (non-blocking), NULL the handle, emit the
            # FAIL row/audit; the pool Close in finally reclaims the runspace.
            if ($PerHostSeconds -gt 0 -and $done -lt $psJobs.Count) {
                $nowPh = Get-Date
                foreach ($pj in $psJobs) {
                    if ($pj.PS -and $pj.StartedAt -and ($nowPh - $pj.StartedAt).TotalSeconds -gt $PerHostSeconds) {
                        try { [void]$pj.PS.BeginStop($null, $null) } catch {}
                        $pj.PS = $null
                        $rowR = & $RowOf ("FAIL: per-host timeout (${PerHostSeconds}s) - host did not finish") $pj.Host $pj.Context
                        [void]$rows.Add($rowR); & $Send (@{ type='row' } + $rowR)
                        & $Send @{ type='audit'; action=$AuditAction; target=$pj.Host; result='Failure'; itemCount=0; detail="per-host timeout (${PerHostSeconds}s)" }
                        & $Send @{ type='log'; level='warn'; text="[$($pj.Host)] abandoned after ${PerHostSeconds}s per-host timeout (in-flight WinRM call being stopped); the rest of the wave continues." }
                        $failCount++; $done++
                        & $Send @{ type='progress'; done=$done; total=$psJobs.Count }
                    }
                }
            }
            if ($done -lt $psJobs.Count) {
                if     ($CancelCheck -and (& $CancelCheck)) { $cancelled = $true }
                elseif ((Get-Date) -gt $deadline)           { $timedOut  = $true }
                if ($cancelled -or $timedOut) {
                    $reason = if ($cancelled) { 'cancelled by operator' } else { "timed out waiting - batch deadline ($([int]$DeadlineSeconds)s) reached" }
                    $abandoned = 0
                    foreach ($pj in $psJobs) {
                        if ($pj.PS) {
                            # BeginStop (non-blocking) then NULL the handle. Do NOT Dispose
                            # here: Dispose right after BeginStop blocks ~11s per host on the
                            # WinRM teardown. The pool Close/Dispose in finally reclaims the
                            # runspaces after all abandon rows/audits are emitted.
                            try { [void]$pj.PS.BeginStop($null, $null) } catch {}
                            $pj.PS = $null
                            $rowR = & $RowOf ("FAIL: $reason (host did not finish)") $pj.Host $pj.Context
                            [void]$rows.Add($rowR); & $Send (@{ type='row' } + $rowR)
                            & $Send @{ type='audit'; action=$AuditAction; target=$pj.Host; result='Failure'; itemCount=0; detail=$reason }
                            $failCount++; $done++; $abandoned++
                        }
                    }
                    & $Send @{ type='log'; level='warn'; text="Run $reason; $abandoned host(s) abandoned mid-flight (in-flight WinRM calls are being stopped)." }
                    break
                }
                Start-Sleep -Milliseconds 120
            }
        }
    } finally {
        try { $pool.Close(); $pool.Dispose() } catch {}
    }

    # Per-run summary -> daily Runs CSV (server-side). One event per fan-out; for a
    # rolled-up card the member names ride along so the server writes one row each.
    if (-not [string]::IsNullOrWhiteSpace($RunAction)) {
        & $Send @{
            type='run'; action=$RunAction; scope=$RunScope; profile=$RunProfile; mode=$RunMode
            hostsTotal=$psJobs.Count; success=$okCount; failed=$failCount
            durationSec=[int]((Get-Date) - $runStart).TotalSeconds
            groupKey=$RunGroupKey; groupMembers=@($RunGroupMembers)
        }
    }

    return [pscustomobject]@{ Rows=@($rows); Ok=$okCount; Failed=$failCount; Skipped=$skipCount; Total=$psJobs.Count; Cancelled=$cancelled; TimedOut=$timedOut }
}

# Parse csvPaths param value (newline-separated paths) into a clean string array.
function Get-AcasCsvPaths {
    param([string]$Raw)
    $out = @()
    if ($Raw) {
        foreach ($p in ($Raw -split '[\r\n]+')) { $pp = $p.Trim().Trim('"'); if ($pp) { $out += $pp } }
    }
    return $out
}

# Parse "profile | host1,host2" job lines into @{ Profile; Hosts }.
function ConvertTo-AcasJobLines {
    param([string]$Raw)
    $out = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrWhiteSpace($Raw)) { return $out }
    foreach ($line in ($Raw -split '[\r\n]+')) {
        $l = $line.Trim()
        if (-not $l) { continue }
        $parts = $l -split '\|', 2
        if ($parts.Count -lt 2) { continue }
        $profile = $parts[0].Trim()
        $hosts   = ConvertTo-AcasHostList $parts[1]
        if ($profile -and $hosts.Count -gt 0) {
            [void]$out.Add(@{ Profile=$profile; Hosts=$hosts })
        }
    }
    return $out
}

# -----------------------------------------------------------------------------
#  KB install worker (lifted from WPT WptKbInstallBlock: MECM CCM_SoftwareUpdate
#  match + InstallUpdates, with an uploaded .msu wusa fallback) + an added
#  UsoClient-trigger method. One job per host. Returns a marker-encoded result
#  string (<<MECM=>> <<MSU=>> <<SKIP=>> <<KBS=>>) for the string fan-out.
# -----------------------------------------------------------------------------
$script:AcasKbInstallBlock = {
    param([string]$Computer, $Cred, [string]$Auth, [string[]]$KBs, [string]$MsuPath, [bool]$NoReboot, [string]$Method)
    $mecmInstalled = 0; $msuInstalled = 0; $skipped = 0
    $errors = New-Object System.Collections.ArrayList
    $details = New-Object System.Collections.ArrayList
    $kbList = ($KBs -join ',')
    $reachable = $false
    foreach ($port in 5985,445) {
        $tc=$null
        try { $tc=New-Object System.Net.Sockets.TcpClient; $iar=$tc.BeginConnect($Computer,$port,$null,$null); if ($iar.AsyncWaitHandle.WaitOne(1500,$false) -and $tc.Connected) { $reachable=$true } } catch {} finally { if ($tc) { try { $tc.Close() } catch {} } }
        if ($reachable) { break }
    }
    if (-not $reachable) { return "FAIL <<MECM=0>> <<MSU=0>> <<SKIP=0>> <<KBS=$kbList>> Offline (no TCP 5985/445)" }
    $wsOpt = New-PSSessionOption -OperationTimeout 1800000 -OpenTimeout 15000 -CancelTimeout 5000 -IdleTimeout 120000
    $splat = @{ ComputerName=$Computer; SessionOption=$wsOpt; ErrorAction='Stop' }
    if ($Cred) { $splat['Credential']=$Cred; $splat['Authentication']=$(if ($Auth) { $Auth } else { 'Negotiate' }) }
    $sess = $null; try { $sess = New-PSSession @splat } catch { return "FAIL <<MECM=0>> <<MSU=0>> <<SKIP=0>> <<KBS=$kbList>> Session failed: $($_.Exception.Message)" }
    try {
        if ($Method -eq 'usoclient') {
            # UsoClient: scan + install all approved WU updates (no per-KB targeting).
            try {
                Invoke-Command -Session $sess -EA Stop -ScriptBlock {
                    Start-Process -FilePath 'UsoClient.exe' -ArgumentList 'StartScan' -WindowStyle Hidden -EA SilentlyContinue
                    Start-Sleep -Seconds 2
                    Start-Process -FilePath 'UsoClient.exe' -ArgumentList 'StartInstall' -WindowStyle Hidden -EA SilentlyContinue
                }
                [void]$details.Add("UsoClient StartScan + StartInstall triggered for $($KBs.Count) requested KB(s)")
            } catch { [void]$errors.Add("UsoClient trigger failed: $($_.Exception.Message)") }
        } else {
            # MECM first: match each requested KB in CCM_SoftwareUpdate then InstallUpdates.
            $mecm = Invoke-Command -Session $sess -ArgumentList (,$KBs) -EA Stop -ScriptBlock {
                param([string[]]$targetKBs)
                $found=@(); $allUpdates=@()
                try { $allUpdates = @(Get-WmiObject -Namespace 'ROOT\ccm\ClientSDK' -Query "SELECT * FROM CCM_SoftwareUpdate WHERE ComplianceState = '0'" -EA Stop) } catch { return @{ Found=@(); Triggered=0; Error="MECM query failed: $($_.Exception.Message)" } }
                foreach ($kb in $targetKBs) { if (@($allUpdates | Where-Object { $_.Name -like "*$kb*" -or $_.ArticleID -eq ($kb -replace '^KB','') }).Count -gt 0) { $found += $kb } }
                if ($found.Count -gt 0) {
                    $toInstall = @($allUpdates | Where-Object { $dom=$false; foreach ($kb in $found) { if ($_.Name -like "*$kb*" -or $_.ArticleID -eq ($kb -replace '^KB','')) { $dom=$true; break } }; $dom })
                    if ($toInstall.Count -gt 0) { try { Invoke-WmiMethod -Class CCM_SoftwareUpdatesManager -Name InstallUpdates -ArgumentList (,$toInstall) -Namespace 'ROOT\ccm\ClientSDK' -EA Stop | Out-Null; return @{ Found=$found; Triggered=$toInstall.Count; Error='' } } catch { return @{ Found=$found; Triggered=0; Error="Install trigger failed: $($_.Exception.Message)" } } }
                }
                return @{ Found=$found; Triggered=0; Error='' }
            }
            if (@($mecm.Found).Count -gt 0 -and $mecm.Triggered -gt 0) { $mecmInstalled = $mecm.Triggered; [void]$details.Add("MECM: triggered $($mecm.Triggered) update(s)") }
            if ($mecm.Error) { [void]$errors.Add($mecm.Error) }
            $handled = @(); if ($mecm.Found) { $handled = @($mecm.Found) }
            $remaining = @($KBs | Where-Object { $handled -notcontains $_ })
            if ($remaining.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($MsuPath)) {
                if (-not (Test-Path -LiteralPath $MsuPath)) { [void]$errors.Add("MSU file not found: $MsuPath") }
                else {
                    Invoke-Command -Session $sess -EA Stop -ScriptBlock { if (-not (Test-Path 'C:\Temp')) { New-Item -Path 'C:\Temp' -ItemType Directory -Force -EA Stop | Out-Null } }
                    $msuName = Split-Path $MsuPath -Leaf
                    try {
                        Copy-Item -LiteralPath $MsuPath -Destination "C:\Temp\$msuName" -ToSession $sess -Force -EA Stop
                        $wusaArgs = "C:\Temp\$msuName /quiet"; if ($NoReboot) { $wusaArgs += ' /norestart' }
                        $exit = Invoke-Command -Session $sess -ArgumentList $wusaArgs -EA Stop -ScriptBlock { param($a) (Start-Process -FilePath 'wusa.exe' -ArgumentList $a -Wait -PassThru -NoNewWindow -EA Stop).ExitCode }
                        if ($exit -eq 0 -or $exit -eq 3010) { $msuInstalled++; [void]$details.Add("MSU $($msuName): installed (exit $exit)") }
                        elseif ($exit -eq 2359302) { $skipped++; [void]$details.Add("MSU $($msuName): already installed") }
                        else { [void]$errors.Add("MSU $msuName exit $exit") }
                        Invoke-Command -Session $sess -ArgumentList $msuName -EA SilentlyContinue -ScriptBlock { param($n) Remove-Item "C:\Temp\$n" -Force -EA SilentlyContinue }
                    } catch { [void]$errors.Add("MSU copy/install: $($_.Exception.Message)") }
                }
            } elseif ($remaining.Count -gt 0) { foreach ($kb in $remaining) { $skipped++; [void]$details.Add("$kb not in MECM, no MSU path - skipped") } }
        }
    } finally { Remove-PSSession $sess -EA SilentlyContinue }
    $installed = [int]$mecmInstalled + [int]$msuInstalled
    $detail = (@($details) -join '; ')
    if (@($errors).Count -gt 0) { $detail = (@($detail, (@($errors) -join '; ')) | Where-Object { $_ }) -join ' | ' }
    $status = if (@($errors).Count -gt 0 -and $installed -eq 0 -and $skipped -eq 0) { 'FAIL' } elseif ($installed -eq 0 -and $skipped -gt 0) { 'SKIP' } else { 'OK' }
    return "$status <<MECM=$mecmInstalled>> <<MSU=$msuInstalled>> <<SKIP=$skipped>> <<KBS=$kbList>> $detail"
}

function Invoke-JanetToolAction {
    param(
        [string]$ActionId,
        [hashtable]$Params,
        [System.Management.Automation.PSCredential]$Credential,
        [scriptblock]$Emit
    )
    $send = { param($e) if ($Emit) { & $Emit $e } }

    # Operator-cancel bridge: the server injects the synchronized job hashtable as
    # $Params['__job']; its 'Cancel' flag (set by POST /api/job/<id>/cancel) lets a
    # running fan-out break and stop in-flight WinRM children. Absent in direct/test
    # calls -> CancelCheck just returns $false.
    $cancelJob = $null
    if ($Params -and $Params.ContainsKey('__job')) { $cancelJob = $Params['__job'] }
    $cancelCheck = { if ($cancelJob) { try { [bool]$cancelJob['Cancel'] } catch { $false } } else { $false } }

    $threads = 20
    if ($Params['threads']) { [int]::TryParse([string]$Params['threads'], [ref]$threads) | Out-Null }
    $threads = [Math]::Max(1, [Math]::Min(32, $threads))

    # Per-host timeout (seconds): the patch/update fan-outs pass this so a single
    # hung host is abandoned on its own clock instead of pinning the wave. 0 = off,
    # so reboot/verify/preflight (which legitimately wait minutes) keep no limit.
    $perHostTimeout = 0
    if ($Params['perHostTimeout']) { [int]::TryParse([string]$Params['perHostTimeout'], [ref]$perHostTimeout) | Out-Null }
    if ($perHostTimeout -lt 0) { $perHostTimeout = 0 }

    $verifyOnly = $false
    if ($null -ne $Params['verifyOnly']) {
        $verifyOnly = ([string]$Params['verifyOnly'] -match '^(?i:true|1|yes|on)$')
    }

    $stamp = { (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') }

    # Resolve the Log4j staged-jar source (override via Params['log4jSource'], else
    # the desktop staging share). Drives auto-runnability + the worker's Copy-Item
    # -ToSession. Only the arms that actually run/verify profiles pay its UNC TCP
    # probe + 2 stat calls - read-only drill-downs (group-findings, findings-for-host,
    # import-acas) skip it so they aren't slowed by a UNC reachability timeout.
    $log4j = @{ Path=''; Ready=$false }
    if (@('analyze-remediation','patch-selected','auto-patch','run-vulnerability','run-all-sequential','run-all-parallel','list-profiles') -contains $ActionId) {
        $log4j = Resolve-AcasLog4jSource -Override ([string]$Params['log4jSource'])
    }

    switch ($ActionId) {

        'import-acas' {
            # Parse CSV file path(s) and/or pasted CSV content, accumulate findings,
            # drop msek-* servers, summarize per host (lifted from Import-WptAcasCsv,
            # Get-WptAcasTargetHosts, btnImportAcas.Add_Click filter logic).
            & $send @{ type='status'; text='Parsing ACAS CSV input...' }
            $paths = Get-AcasCsvPaths ([string]$Params['csvPaths'])

            # Reuse the shared ACAS CSV parser (host-pick DNS>NetBIOS>IP + msek server
            # skip + column map - same code analyze-remediation uses). Call it once per
            # source so we still emit one summary audit row per file, then bucket the
            # returned findings by host below.
            $allFindings = New-Object System.Collections.ArrayList
            $fileAudits  = New-Object System.Collections.ArrayList   # one summary audit per parsed source
            $totalRows = 0
            $serversSkipped = 0
            foreach ($path in $paths) {
                if (-not (Test-Path -LiteralPath $path)) {
                    & $send @{ type='log'; level='warn'; text="File not found: $path" }
                    continue
                }
                $parsed = ConvertFrom-AcasCsv -Paths @($path) -Send $send
                foreach ($f in $parsed.Findings) { [void]$allFindings.Add($f) }
                $totalRows += [int]$parsed.RowCount
                $serversSkipped += [int]$parsed.ServersSkipped
                [void]$fileAudits.Add(@{ Target=(Split-Path -Path $path -Leaf); Rows=[int]$parsed.RowCount })
            }
            if ($Params['csvText'] -and -not [string]::IsNullOrWhiteSpace([string]$Params['csvText'])) {
                $parsed = ConvertFrom-AcasCsv -Text ([string]$Params['csvText']) -Send $send
                foreach ($f in $parsed.Findings) { [void]$allFindings.Add($f) }
                $totalRows += [int]$parsed.RowCount
                $serversSkipped += [int]$parsed.ServersSkipped
                [void]$fileAudits.Add(@{ Target='(pasted CSV)'; Rows=[int]$parsed.RowCount })
            }

            if ($totalRows -eq 0) {
                & $send @{ type='log'; level='warn'; text='No CSV rows parsed. Provide a valid file path or paste CSV content.' }
                return @{ rows=@(); summary=@{ total=0; ok=0; failed=0 } }
            }

            $byHost = @{}     # host -> @{ Findings=int; Plugins=HashSet; MaxSev=string }
            $sevRank = @{ 'critical'=4; 'high'=3; 'medium'=2; 'low'=1; 'info'=0; 'informational'=0 }
            foreach ($f in $allFindings) {
                $pick = [string]$f.Host
                if (-not $byHost.ContainsKey($pick)) {
                    $byHost[$pick] = @{ Findings=0; Plugins=(New-Object 'System.Collections.Generic.HashSet[string]'); MaxSevRank=-1; MaxSev='' }
                }
                $h = $byHost[$pick]
                $h.Findings++
                if ($f.PluginId) { [void]$h.Plugins.Add([string]$f.PluginId) }
                $sev = [string]$f.Severity
                if ($sev) {
                    $rank = if ($sevRank.ContainsKey($sev.ToLower())) { $sevRank[$sev.ToLower()] } else { 0 }
                    if ($rank -gt $h.MaxSevRank) { $h.MaxSevRank = $rank; $h.MaxSev = $sev }
                }
            }

            & $send @{ type='status'; text="Parsed $($totalRows) row(s) across $($byHost.Count) host(s); $serversSkipped server row(s) skipped." }

            $rows = New-Object System.Collections.ArrayList
            $i = 0
            foreach ($hostName in ($byHost.Keys | Sort-Object)) {
                $i++
                $h = $byHost[$hostName]
                $row = @{
                    Host             = $hostName
                    'Findings Added' = $h.Findings
                    'Severity (max)' = $(if ($h.MaxSev) { $h.MaxSev } else { 'n/a' })
                    'Plugins'        = $h.Plugins.Count
                    'Servers Skipped'= $serversSkipped
                }
                [void]$rows.Add($row)
                & $send (@{ type='row' } + $row)
                & $send @{ type='progress'; done=$i; total=$byHost.Count }
            }

            # Read-only parse: ONE summary audit per CSV source (per-host data stays
            # in the row events above - no per-host TouchHost attribution rows).
            foreach ($fa in $fileAudits) {
                & $send @{ type='audit'; action='TouchHost'; target=[string]$fa.Target; result='Success';
                           itemCount=[int]$fa.Rows; detail="ACAS CSV import (read-only parse): $($fa.Rows) finding row(s); $($byHost.Count) host(s) total; $serversSkipped server row(s) skipped" }
            }

            & $send @{ type='status'; text="Done. $($byHost.Count) host(s), $($totalRows) finding(s), $serversSkipped server row(s) skipped." }
            return @{ rows=@($rows); summary=@{ total=$byHost.Count; ok=$byHost.Count; failed=0; findings=$totalRows; serversSkipped=$serversSkipped } }
        }

        'analyze-remediation' {
            # Read-only "what can I patch?" view. Parse CSV -> classify each
            # vulnerability group -> one row per plugin with its category,
            # matched profile, affected host count and auto-runnability.
            & $send @{ type='status'; text='Parsing ACAS CSV and matching remediation profiles...' }
            $paths = Get-AcasCsvPaths ([string]$Params['csvPaths'])
            $parsed = ConvertFrom-AcasCsv -Paths $paths -Text ([string]$Params['csvText']) -Send $send
            if ($parsed.Findings.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No findings parsed. Provide a valid ACAS CSV.' }
                return @{ rows=@(); summary=@{ total=0; ok=0; failed=0 } }
            }
            & $send @{ type='status'; text="Parsed $($parsed.RowCount) row(s); $($parsed.ServersSkipped) server row(s) skipped. Classifying..." }

            $groups = @(Get-AcasRemediationGroups -Findings $parsed.Findings)   # rolled up: one card per product/profile, latest version
            $rows = New-Object System.Collections.ArrayList
            $cardGroups = New-Object System.Collections.ArrayList   # compact, host-arrays omitted (re-derived server-side at patch time)
            $patchableHosts = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            $counts = @{ Patchable=0; Experimental=0; Reboot=0; Unpatchable=0; NotUpdatable=0 }
            $autoRunnable = 0
            $i = 0
            foreach ($g in $groups) {
                $i++
                if ($counts.ContainsKey($g.Category)) { $counts[$g.Category]++ }
                $prof = if ($g.ProfileNames.Count -gt 0) { $g.ProfileNames[0] } else { '' }
                $runnable = $false
                if (($g.Category -eq 'Patchable' -or $g.Category -eq 'Experimental') -and $prof) {
                    $runnable = Test-AcasProfileAutoRunnable -ProfileName $prof -StagingReady $log4j.Ready
                }
                if ($runnable) { $autoRunnable++; foreach ($h in $g.Hosts) { [void]$patchableHosts.Add($h) } }
                $row = @{
                    Category          = $g.Category
                    Plugin            = $g.DisplayName
                    Severity          = $(if ($g.Severity) { $g.Severity } else { 'n/a' })
                    Hosts             = $g.HostCount
                    'Matched Profile' = $(if ($prof) { $prof } else { '(none)' })
                    'Auto-Runnable'   = $(if ($runnable) { 'yes' } elseif ($g.Category -eq 'Patchable' -or $g.Category -eq 'Experimental') { 'needs staging' } else { 'no' })
                    CVEs              = $(if ($g.Cves.Count -gt 0) { ($g.Cves -join ', ') } else { '' })
                }
                [void]$rows.Add($row)
                # Compact card descriptor for the unified Remediation UI (one card per
                # rolled-up product: checkbox + host COUNT + profile variant picker).
                # members > 1 means several plugins were combined onto this card.
                $solPreview = [string]$g.Solution
                if ($solPreview.Length -gt 600) { $solPreview = $solPreview.Substring(0,600) + '...' }
                [void]$cardGroups.Add(@{
                    key       = $g.Key
                    plugin    = $g.DisplayName
                    category  = $g.Category
                    severity  = $(if ($g.Severity) { $g.Severity } else { '' })
                    hostCount = $g.HostCount
                    hosts     = @($g.Hosts)   # affected host list, so the UI can dispatch run-vulnerability against explicit (operator-reviewable) targets
                    profiles  = @($g.ProfileNames)
                    runnable  = $runnable
                    # needsStaging: the matched profile replaces staged files (Log4j jars)
                    # that must be readable by the host. The UI uses this to explain a
                    # greyed card ("set/Browse a Log4j source") instead of "no profile".
                    needsStaging = $(if ($prof -and $script:AcasUpdateProfiles.ContainsKey($prof) -and ($script:AcasUpdateProfiles[$prof] -is [hashtable]) -and $script:AcasUpdateProfiles[$prof].ContainsKey('NeedsStaging')) { [bool]$script:AcasUpdateProfiles[$prof]['NeedsStaging'] } else { $false })
                    members   = $g.MemberCount
                    memberNames = @($g.MemberNames | Select-Object -First 40)
                    cves      = @($g.Cves | Select-Object -First 8)
                    solution  = $solPreview
                })
                & $send (@{ type='row' } + $row)
                & $send @{ type='progress'; done=$i; total=$groups.Count }
            }

            & $send @{ type='status'; text="Done. $($groups.Count) vuln group(s): $($counts.Patchable) patchable, $($counts.Experimental) experimental, $($counts.Reboot) reboot, $($counts.Unpatchable) unpatchable, $($counts.NotUpdatable) not-updatable. $autoRunnable auto-runnable group(s) covering $($patchableHosts.Count) host(s)." }
            & $send @{ type='log'; level='info'; text="Auto-Patch would run $autoRunnable matched group(s) across $($patchableHosts.Count) host(s). Reboot/Unpatchable/staged groups are listed above as coverage gaps." }
            $uniqueHosts = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($f in $parsed.Findings) { if ($f.Host) { [void]$uniqueHosts.Add([string]$f.Host) } }
            return @{ rows=@($rows); groups=@($cardGroups); summary=@{
                total=$groups.Count; ok=$autoRunnable; failed=0;
                patchable=$counts.Patchable; experimental=$counts.Experimental; reboot=$counts.Reboot;
                unpatchable=$counts.Unpatchable; notUpdatable=$counts.NotUpdatable;
                autoRunnableHosts=$patchableHosts.Count;
                findings=$parsed.Findings.Count; uniqueHosts=$uniqueHosts.Count;
                serversSkipped=$parsed.ServersSkipped; importStamp=(& $stamp) } }
        }

        'patch-selected' {
            # Backend for the unified Remediation UI's "Patch Selected" / "Test
            # Selected". Re-parse the CSV, re-group, then patch ONLY the operator-
            # checked vuln groups using the per-card chosen profile. Host sets are
            # re-derived here (never shipped to the browser); (profile,host) tuples
            # are de-duped so two plugins -> one profile -> one host = one action.
            $sels = @()
            if ($Params['selections']) { $sels = @($Params['selections']) }
            if ($sels.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No remediations selected.' }
                return @{ rows=@(); summary=@{ total=0; ok=0; failed=0 } }
            }
            & $send @{ type='status'; text='Re-parsing ACAS CSV for the selected remediations...' }
            $paths = Get-AcasCsvPaths ([string]$Params['csvPaths'])
            $parsed = ConvertFrom-AcasCsv -Paths $paths -Text ([string]$Params['csvText']) -Send $send
            if ($parsed.Findings.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No findings parsed from the CSV.' }
                return @{ rows=@(); summary=@{ total=0; ok=0; failed=0 } }
            }
            $groups = @(Get-AcasRemediationGroups -Findings $parsed.Findings)   # same rollup as analyze, so a combined card patches the union of hosts
            $byKey = @{}
            foreach ($g in $groups) { $byKey[$g.Key] = $g }

            $profilesTable = $script:AcasUpdateProfiles
            $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            $groupRuns = New-Object System.Collections.ArrayList   # one fan-out per selected group -> per-member Runs CSV fidelity
            $jobTotal = 0
            $picked = 0; $skipped = 0
            foreach ($sel in $sels) {
                $key = ''; $prof = ''; $hostFilter = $null
                if ($sel -is [string]) {
                    $key = [string]$sel
                } elseif ($sel -is [System.Collections.IDictionary]) {
                    if ($sel.Contains('key'))     { $key  = [string]$sel['key'] }
                    if ($sel.Contains('profile')) { $prof = [string]$sel['profile'] }
                    if ($sel.Contains('hosts') -and $sel['hosts']) { $hostFilter = @($sel['hosts']) }
                } else {
                    # PSCustomObject (from a JSON request body)
                    if ($sel.PSObject.Properties['key'])     { $key  = [string]$sel.key }
                    if ($sel.PSObject.Properties['profile']) { $prof = [string]$sel.profile }
                    if ($sel.PSObject.Properties['hosts'] -and $sel.hosts) { $hostFilter = @($sel.hosts) }
                }
                if (-not $key -or -not $byKey.ContainsKey($key)) { $skipped++; continue }
                $g = $byKey[$key]
                # Resolve the chosen profile: honor the card pick if valid, else the group's default.
                if (-not $prof -or ($g.ProfileNames -notcontains $prof)) {
                    $prof = if ($g.ProfileNames.Count -gt 0) { $g.ProfileNames[0] } else { '' }
                }
                if (-not $prof) { $skipped++; continue }
                # A verify/dry-run is harmless for package/staging profiles (the worker
                # supports it), so only enforce auto-runnability on a real patch run.
                if (-not $verifyOnly -and -not (Test-AcasProfileAutoRunnable -ProfileName $prof -StagingReady $log4j.Ready)) {
                    $skipped++
                    & $send @{ type='log'; level='warn'; text="Skipping '$($g.DisplayName)' -> '$prof' on $($g.HostCount) host(s): needs controller-side staging (package / Log4j jars)." }
                    continue
                }
                # Optional per-card host filter from the per-finding grid: restrict to the
                # operator-checked hosts (canonicalized to short form, same as the group's).
                $runHosts = @($g.Hosts)
                if ($null -ne $hostFilter -and @($hostFilter).Count -gt 0) {
                    $allow = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                    foreach ($hf in $hostFilter) { $sh = Get-AcasShortHost ([string]$hf); if ($sh) { [void]$allow.Add($sh) } }
                    $runHosts = @($g.Hosts | Where-Object { $allow.Contains($_) })
                    if ($runHosts.Count -eq 0) { $skipped++; continue }
                }
                $picked++
                $jobs = New-Object System.Collections.ArrayList
                foreach ($h in $runHosts) {
                    $tupleKey = "$prof|$h"
                    if ($seen.Add($tupleKey)) {
                        [void]$jobs.Add(@{ Host=$h; Args=@($h, $prof, $profilesTable, [bool]$verifyOnly, $Credential, $log4j.Path); Context=@{ Profile=$prof } })
                    }
                }
                if ($jobs.Count -gt 0) {
                    [void]$groupRuns.Add(@{ Group=$g; Profile=$prof; Jobs=$jobs })
                    $jobTotal += $jobs.Count
                } else {
                    & $send @{ type='log'; level='info'; text="'$($g.DisplayName)' -> '$prof': every (profile,host) action already covered by an earlier selection." }
                }
            }
            if ($jobTotal -eq 0) {
                & $send @{ type='log'; level='warn'; text='Nothing runnable in the selection (all skipped or no profile).' }
                return @{ rows=@(); summary=@{ total=0; ok=0; failed=0; skipped=$skipped } }
            }
            $mode = if ($verifyOnly) { 'TEST/VERIFY (dry run)' } else { 'PATCH' }
            & $send @{ type='status'; text="${mode}: $picked selected group(s) -> $jobTotal unique (profile,host) action(s), $threads thread(s)..." }

            $rowOf = $script:AcasUpdateRowOf
            $okOf  = $script:AcasOkOf
            $detOf = $script:AcasDetOfProfile

            # One fan-out per selected group, drained sequentially, so the daily Runs
            # CSV gets GroupKey + member vuln names + profile per group (desktop
            # Write-NemRunSummary fidelity for per-CVE reporting). The (profile,host)
            # dedup above already removed overlap between groups.
            $allRows = New-Object System.Collections.ArrayList
            $okTotal = 0; $failTotal = 0; $total = 0
            $gi = 0
            foreach ($gr in $groupRuns) {
                $gi++
                $grp = $gr.Group
                & $send @{ type='status'; text="[$gi/$($groupRuns.Count)] ${mode}: '$($gr.Profile)' for [$($grp.DisplayName)] on $($gr.Jobs.Count) host(s)..." }
                $fan = Invoke-AcasFanOut -Jobs @($gr.Jobs) -Work $script:AcasUpdateWorker -Threads $threads `
                           -RowOf $rowOf -OkOf $okOf -AuditAction $(if ($verifyOnly) { 'TouchHost' } else { 'VulnPatched' }) -AuditDetailOf $detOf -Send $send -CancelCheck $cancelCheck `
                           -RunAction $(if ($verifyOnly) { 'VulnVerify' } else { 'VulnRun' }) -RunScope $grp.DisplayName -RunProfile $gr.Profile -RunMode $(if ($verifyOnly) { 'Verify' } else { 'Update' }) `
                           -RunGroupKey $grp.Key -RunGroupMembers @($grp.MemberNames)
                $okTotal += $fan.Ok; $failTotal += $fan.Failed; $total += $fan.Total
                foreach ($r in $fan.Rows) { [void]$allRows.Add($r) }
                # Operator cancel during a group stops that group's in-flight work;
                # do NOT start the remaining selected groups.
                if ($fan.Cancelled -or (& $cancelCheck)) {
                    & $send @{ type='log'; level='warn'; text='Cancelled by operator; remaining selected group(s) not started.' }
                    break
                }
            }
            & $send @{ type='status'; text="Done. $okTotal ok, $failTotal failed of $total action(s). $skipped selection(s) skipped." }
            return @{ rows=@($allRows); summary=@{ total=$total; ok=$okTotal; failed=$failTotal; groups=$picked; skipped=$skipped; mode=$(if ($verifyOnly) { 'verify' } else { 'patch' }) } }
        }

        'auto-patch' {
            # The headline workflow: import CSV -> match -> auto-patch every
            # affected host. Group findings, pick each Patchable group's profile,
            # de-dupe (profile, host) work, and fan out the same per-host engine
            # used by run-vulnerability. Coverage gaps are logged, not run.
            $includeExperimental = $false
            if ($null -ne $Params['includeExperimental']) {
                $includeExperimental = ([string]$Params['includeExperimental'] -match '^(?i:true|1|yes|on)$')
            }
            $preferSC = $false
            if ($null -ne $Params['preferSoftwareCenter']) {
                $preferSC = ([string]$Params['preferSoftwareCenter'] -match '^(?i:true|1|yes|on)$')
            }

            & $send @{ type='status'; text='Parsing ACAS CSV and matching remediation profiles...' }
            $paths = Get-AcasCsvPaths ([string]$Params['csvPaths'])
            $parsed = ConvertFrom-AcasCsv -Paths $paths -Text ([string]$Params['csvText']) -Send $send
            if ($parsed.Findings.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No findings parsed. Provide a valid ACAS CSV.' }
                return @{ rows=@(); summary=@{ total=0; ok=0; failed=0 } }
            }
            $groups = @(Get-AcasVulnGroups -Findings $parsed.Findings)

            # Resolve each runnable group's chosen profile and accumulate unique
            # (profile, host) tuples. Two plugins that route to the same profile
            # on the same host collapse to a single patch action.
            $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            $jobs = New-Object System.Collections.ArrayList
            $gapReboot = 0; $gapUnpatch = 0; $gapNotUpd = 0; $gapStaging = 0
            $runnableGroups = 0
            $profilesTable = $script:AcasUpdateProfiles

            foreach ($g in $groups) {
                $isCandidate = ($g.Category -eq 'Patchable') -or ($includeExperimental -and $g.Category -eq 'Experimental')
                if (-not $isCandidate) {
                    switch ($g.Category) {
                        'Reboot'       { $gapReboot++ }
                        'Unpatchable'  { $gapUnpatch++ }
                        'NotUpdatable' { $gapNotUpd++ }
                        'Experimental' { $gapNotUpd++ }
                    }
                    continue
                }
                if ($g.ProfileNames.Count -eq 0) { $gapNotUpd++; continue }

                # Choose variant: default = first profile; optionally prefer a
                # "* - Software Center" alternate when one is in the matched list.
                $chosen = $g.ProfileNames[0]
                if ($preferSC) {
                    $sc = @($g.ProfileNames | Where-Object { $_ -like '* - Software Center' })
                    if ($sc.Count -gt 0) { $chosen = $sc[0] }
                }
                if (-not $verifyOnly -and -not (Test-AcasProfileAutoRunnable -ProfileName $chosen -StagingReady $log4j.Ready)) {
                    $gapStaging++
                    & $send @{ type='log'; level='warn'; text="Skipping '$($g.DisplayName)' -> '$chosen' on $($g.HostCount) host(s): needs controller-side staging (package / Log4j jars). Run it from the workstation patching tool or a single manual run." }
                    continue
                }
                $runnableGroups++
                foreach ($h in $g.Hosts) {
                    $tupleKey = "$chosen|$h"
                    if ($seen.Add($tupleKey)) {
                        [void]$jobs.Add(@{ Host=$h; Args=@($h, $chosen, $profilesTable, [bool]$verifyOnly, $Credential, $log4j.Path); Context=@{ Profile=$chosen } })
                    }
                }
            }

            $gapTotal = $gapReboot + $gapUnpatch + $gapNotUpd + $gapStaging
            if ($gapTotal -gt 0) {
                & $send @{ type='log'; level='info'; text="Coverage gaps (not auto-run): $gapReboot reboot-required, $gapUnpatch unpatchable, $gapStaging needs-staging, $gapNotUpd no-profile group(s)." }
            }
            if ($jobs.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='Nothing auto-runnable in this CSV. Use Analyze to see the breakdown, or handle the coverage gaps manually.' }
                return @{ rows=@(); summary=@{ total=0; ok=0; failed=0; gaps=$gapTotal } }
            }

            $mode = if ($verifyOnly) { 'VERIFY (dry run)' } else { 'AUTO-PATCH' }
            & $send @{ type='status'; text="${mode}: $($runnableGroups) matched group(s) -> $($jobs.Count) unique (profile,host) action(s), $threads thread(s)..." }

            $rowOf = $script:AcasUpdateRowOf
            $okOf  = $script:AcasOkOf
            $detOf = $script:AcasDetOfProfile

            $fan = Invoke-AcasFanOut -Jobs $jobs -Work $script:AcasUpdateWorker -Threads $threads -PerHostSeconds $perHostTimeout `
                       -RowOf $rowOf -OkOf $okOf -AuditAction $(if ($verifyOnly) { 'TouchHost' } else { 'VulnPatched' }) -AuditDetailOf $detOf -Send $send -CancelCheck $cancelCheck `
                       -RunAction $(if ($verifyOnly) { 'VulnVerify' } else { 'VulnRun' }) -RunScope "Auto-patch: $runnableGroups matched group(s)" -RunMode $(if ($verifyOnly) { 'Verify' } else { 'Update' })
            & $send @{ type='status'; text="Done. $($fan.Ok) ok, $($fan.Failed) failed of $($fan.Total) action(s). $gapTotal coverage gap(s) not run." }
            return @{ rows=$fan.Rows; summary=@{ total=$fan.Total; ok=$fan.Ok; failed=$fan.Failed; groups=$runnableGroups; gaps=$gapTotal; mode=$(if ($verifyOnly) { 'verify' } else { 'patch' }) } }
        }

        'run-vulnerability' {
            $profileName = [string]$Params['profileName']
            $vulnDisplay = [string]$Params['vulnDisplay']
            if (-not $vulnDisplay) { $vulnDisplay = $profileName }
            if (-not $script:AcasUpdateProfiles.ContainsKey($profileName)) {
                & $send @{ type='log'; level='err'; text="Unknown profile '$profileName'. Available: $($script:AcasUpdateProfiles.Keys -join '; ')" }
                return @{ rows=@(); summary=@{ total=0; ok=0; failed=0 } }
            }
            $targets = ConvertTo-AcasHostList ([string]$Params['targets'])
            if ($targets.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No valid targets.' }
                return @{ rows=@(); summary=@{ total=0; ok=0; failed=0 } }
            }
            $mode = if ($verifyOnly) { 'Verify' } else { 'Update' }
            & $send @{ type='status'; text="$mode '$profileName' for [$vulnDisplay] on $($targets.Count) host(s), $threads thread(s)..." }

            $profilesTable = $script:AcasUpdateProfiles
            $jobs = New-Object System.Collections.ArrayList
            foreach ($t in $targets) {
                [void]$jobs.Add(@{ Host=$t; Args=@($t, $profileName, $profilesTable, [bool]$verifyOnly, $Credential, $log4j.Path); Context=@{ Profile=$profileName; Mode=$mode } })
            }

            $rowOf = {
                param($res, $hostName, $ctx)
                $pre  = Get-AcasMarker $res 'PRE'
                $post = Get-AcasMarker $res 'POST'
                @{
                    Host             = $hostName
                    Result           = $(if ($res -like 'FAIL*') { 'FAIL' } elseif ($res -like 'SKIP*') { 'SKIP' } else { 'OK' })
                    'Version Before' = $(if ($pre)  { $pre }  else { 'n/a' })
                    'Version After'  = $(if ($post) { $post } else { 'n/a' })
                    Mode             = $ctx.Mode
                    Timestamp        = (& $stamp)
                    Detail           = (Remove-AcasMarkers $res)
                }
            }
            $okOf  = $script:AcasOkOf
            $detOf = $script:AcasDetOfProfile

            # Optional rollup info from the card: groupKey + member vuln names so the
            # daily Runs CSV fans out one row per member (desktop Write-NemRunSummary).
            $runMembers = @()
            if ($Params['members']) { $runMembers = @(([string]$Params['members'] -split '[\r\n]+') | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
            $runGroupKey = [string]$Params['groupKey']

            $fan = Invoke-AcasFanOut -Jobs $jobs -Work $script:AcasUpdateWorker -Threads $threads -PerHostSeconds $perHostTimeout `
                       -RowOf $rowOf -OkOf $okOf -AuditAction $(if ($verifyOnly) { 'TouchHost' } else { 'VulnPatched' }) -AuditDetailOf $detOf -Send $send -CancelCheck $cancelCheck `
                       -RunAction $(if ($verifyOnly) { 'VulnVerify' } else { 'VulnRun' }) -RunScope $vulnDisplay -RunProfile $profileName -RunMode $mode `
                       -RunGroupKey $runGroupKey -RunGroupMembers $runMembers
            & $send @{ type='status'; text="Done. $($fan.Ok) ok, $($fan.Failed) failed of $($fan.Total)." }
            return @{ rows=$fan.Rows; summary=@{ total=$fan.Total; ok=$fan.Ok; failed=$fan.Failed; profile=$profileName } }
        }

        { $_ -eq 'run-all-sequential' -or $_ -eq 'run-all-parallel' } {
            $jobLines = ConvertTo-AcasJobLines ([string]$Params['jobs'])
            if ($jobLines.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text="No valid jobs. Each line must be 'profile | host1,host2,...'." }
                return @{ rows=@(); summary=@{ total=0; ok=0; failed=0 } }
            }
            $mode = if ($verifyOnly) { 'Verify' } else { 'Update' }
            $profilesTable = $script:AcasUpdateProfiles

            $rowOf = $script:AcasUpdateRowOf
            $okOf  = $script:AcasOkOf
            $detOf = $script:AcasDetOfProfile

            $allRows = New-Object System.Collections.ArrayList
            $okTotal = 0; $failTotal = 0; $total = 0

            if ($ActionId -eq 'run-all-parallel') {
                # Submit every (profile, host) tuple up-front.
                & $send @{ type='status'; text="BULK ${mode}: $($jobLines.Count) profile group(s), $threads thread(s)..." }
                $jobs = New-Object System.Collections.ArrayList
                foreach ($jl in $jobLines) {
                    if (-not $profilesTable.ContainsKey($jl.Profile)) {
                        & $send @{ type='log'; level='warn'; text="Skipping unknown profile '$($jl.Profile)'." }
                        continue
                    }
                    foreach ($t in $jl.Hosts) {
                        [void]$jobs.Add(@{ Host=$t; Args=@($t, $jl.Profile, $profilesTable, [bool]$verifyOnly, $Credential, $log4j.Path); Context=@{ Profile=$jl.Profile } })
                    }
                }
                if ($jobs.Count -eq 0) {
                    & $send @{ type='log'; level='warn'; text='No runnable (profile, host) tuples.' }
                    return @{ rows=@(); summary=@{ total=0; ok=0; failed=0 } }
                }
                $fan = Invoke-AcasFanOut -Jobs $jobs -Work $script:AcasUpdateWorker -Threads $threads -PerHostSeconds $perHostTimeout `
                           -RowOf $rowOf -OkOf $okOf -AuditAction $(if ($verifyOnly) { 'TouchHost' } else { 'VulnPatched' }) -AuditDetailOf $detOf -Send $send -CancelCheck $cancelCheck `
                           -RunAction $(if ($verifyOnly) { 'VulnVerify' } else { 'VulnRun' }) -RunScope "Bulk parallel: $($jobLines.Count) profile group(s)" -RunMode $mode
                $okTotal = $fan.Ok; $failTotal = $fan.Failed; $total = $fan.Total
                foreach ($r in $fan.Rows) { [void]$allRows.Add($r) }
            }
            else {
                # Sequential: one profile group at a time, drain before next.
                & $send @{ type='status'; text="RUN ALL (sequential): $($jobLines.Count) profile group(s), $threads thread(s)..." }
                $g = 0
                foreach ($jl in $jobLines) {
                    $g++
                    if (-not $profilesTable.ContainsKey($jl.Profile)) {
                        & $send @{ type='log'; level='warn'; text="Skipping unknown profile '$($jl.Profile)'." }
                        continue
                    }
                    & $send @{ type='status'; text="[$g/$($jobLines.Count)] $mode '$($jl.Profile)' on $($jl.Hosts.Count) host(s)..." }
                    $jobs = New-Object System.Collections.ArrayList
                    foreach ($t in $jl.Hosts) {
                        [void]$jobs.Add(@{ Host=$t; Args=@($t, $jl.Profile, $profilesTable, [bool]$verifyOnly, $Credential, $log4j.Path); Context=@{ Profile=$jl.Profile } })
                    }
                    $fan = Invoke-AcasFanOut -Jobs $jobs -Work $script:AcasUpdateWorker -Threads $threads -PerHostSeconds $perHostTimeout `
                               -RowOf $rowOf -OkOf $okOf -AuditAction $(if ($verifyOnly) { 'TouchHost' } else { 'VulnPatched' }) -AuditDetailOf $detOf -Send $send -CancelCheck $cancelCheck `
                               -RunAction $(if ($verifyOnly) { 'VulnVerify' } else { 'VulnRun' }) -RunScope $jl.Profile -RunProfile $jl.Profile -RunMode $mode
                    $okTotal += $fan.Ok; $failTotal += $fan.Failed; $total += $fan.Total
                    foreach ($r in $fan.Rows) { [void]$allRows.Add($r) }
                    # Operator cancel during a group stops that group's in-flight work;
                    # do NOT start the remaining profile groups - otherwise destructive
                    # updates keep firing on hosts the operator just tried to spare.
                    if ($fan.Cancelled -or (& $cancelCheck)) {
                        & $send @{ type='log'; level='warn'; text='Cancelled by operator; remaining profile group(s) not started.' }
                        break
                    }
                }
            }

            & $send @{ type='status'; text="Done. $okTotal ok, $failTotal failed of $total." }
            return @{ rows=@($allRows); summary=@{ total=$total; ok=$okTotal; failed=$failTotal } }
        }

        'schedule-reboot' {
            $targets = ConvertTo-AcasHostList ([string]$Params['targets'])
            if ($targets.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No valid targets.' }
                return @{ rows=@(); summary=@{ total=0; ok=0; failed=0 } }
            }
            $vulnDisplay = [string]$Params['vulnDisplay']; if (-not $vulnDisplay) { $vulnDisplay = 'Scheduled Reboot' }
            $warn = [string]$Params['warningText']
            if ([string]::IsNullOrWhiteSpace($warn)) { $warn = 'This workstation will reboot in 5 minutes for required security updates. Save your work now.' }
            & $send @{ type='status'; text="Scheduling reboot on $($targets.Count) host(s) for [$vulnDisplay]..." }

            $jobs = New-Object System.Collections.ArrayList
            foreach ($t in $targets) { [void]$jobs.Add(@{ Host=$t; Args=@($t, $warn, $Credential); Context=@{} }) }

            $rowOf = {
                param($res, $hostName, $ctx)
                @{
                    Host        = $hostName
                    Result      = $(if ($res -like 'FAIL*') { 'failed' } elseif ($res -match 'already') { 'already-pending' } else { 'scheduled' })
                    'Exit Code' = (Get-AcasMarker $res 'EXIT')
                    Timestamp   = (& $stamp)
                    Detail      = (Remove-AcasMarkers $res)
                }
            }
            $okOf  = $script:AcasOkOf
            $detOf = $script:AcasDetOfPlain

            $fan = Invoke-AcasFanOut -Jobs $jobs -Work $script:AcasRebootWorker -Threads $threads `
                       -RowOf $rowOf -OkOf $okOf -AuditAction 'VulnPatched' -AuditDetailOf $detOf -Send $send -CancelCheck $cancelCheck `
                       -RunAction 'Reboot' -RunScope $vulnDisplay -RunMode 'Reboot'
            & $send @{ type='status'; text="Done. $($fan.Ok) ok, $($fan.Failed) failed of $($fan.Total)." }
            return @{ rows=$fan.Rows; summary=@{ total=$fan.Total; ok=$fan.Ok; failed=$fan.Failed } }
        }

        'verify-post-reboot' {
            $targets = ConvertTo-AcasHostList ([string]$Params['targets'])
            if ($targets.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No valid targets.' }
                return @{ rows=@(); summary=@{ total=0; ok=0; failed=0 } }
            }
            $vulnDisplay = [string]$Params['vulnDisplay']; if (-not $vulnDisplay) { $vulnDisplay = 'Reboot Verify' }
            & $send @{ type='status'; text="Verifying post-reboot state on $($targets.Count) host(s) (up to 10min/host wait)..." }

            $jobs = New-Object System.Collections.ArrayList
            foreach ($t in $targets) { [void]$jobs.Add(@{ Host=$t; Args=@($t, $Credential); Context=@{} }) }

            $rowOf = {
                param($res, $hostName, $ctx)
                @{
                    Host            = $hostName
                    Reachable       = (Get-AcasMarker $res 'REACH')
                    RebootPending   = (Get-AcasMarker $res 'PENDING')
                    'OS Build'      = (Get-AcasMarker $res 'BUILD')
                    Result          = $(if ($res -like 'FAIL*') { 'FAIL' } else { 'OK' })
                    Timestamp       = (& $stamp)
                    Detail          = (Remove-AcasMarkers $res)
                }
            }
            $okOf  = $script:AcasOkOf
            $detOf = $script:AcasDetOfPlain

            # Verify is a read/check, not a state change -> TouchHost audit. Each
            # worker legitimately waits up to 10 min for its host to come back, so
            # the batch deadline scales with the wave count.
            $verifyDeadline = ([int][Math]::Ceiling($jobs.Count / [double][Math]::Max(1, $threads)) * 660) + 300
            $fan = Invoke-AcasFanOut -Jobs $jobs -Work $script:AcasRebootVerifyWorker -Threads $threads `
                       -RowOf $rowOf -OkOf $okOf -AuditAction 'TouchHost' -AuditDetailOf $detOf -Send $send -CancelCheck $cancelCheck `
                       -RunAction 'RebootVerify' -RunScope $vulnDisplay -RunMode 'Verify' -DeadlineSeconds $verifyDeadline
            & $send @{ type='status'; text="Done. $($fan.Ok) ok, $($fan.Failed) failed of $($fan.Total)." }
            return @{ rows=$fan.Rows; summary=@{ total=$fan.Total; ok=$fan.Ok; failed=$fan.Failed } }
        }

        'preflight-services' {
            $targets = ConvertTo-AcasHostList ([string]$Params['targets'])
            if ($targets.Count -eq 0) {
                & $send @{ type='log'; level='warn'; text='No valid targets.' }
                return @{ rows=@(); summary=@{ total=0; ok=0; failed=0 } }
            }
            & $send @{ type='status'; text="Pre-flight services (winrm, Winmgmt, RemoteRegistry) on $($targets.Count) host(s)..." }

            $jobs = New-Object System.Collections.ArrayList
            foreach ($t in $targets) { [void]$jobs.Add(@{ Host=$t; Args=@($t, $Credential, 'Negotiate'); Context=@{} }) }

            $rowOf = {
                param($res, $hostName, $ctx)
                $chg = Get-AcasMarker $res 'CHANGES'
                @{
                    Host          = $hostName
                    'Changes Made'= $(if ($chg) { $chg } else { 'already correct' })
                    Result        = $(if ($res -like 'FAIL*') { 'FAIL' } else { 'OK' })
                    Timestamp     = (& $stamp)
                    Detail        = (Remove-AcasMarkers $res)
                }
            }
            $okOf  = $script:AcasOkOf
            $detOf = $script:AcasDetOfPlain

            $fan = Invoke-AcasFanOut -Jobs $jobs -Work $script:AcasPreflightWorker -Threads $threads `
                       -RowOf $rowOf -OkOf $okOf -AuditAction 'TouchHost' -AuditDetailOf $detOf -Send $send -CancelCheck $cancelCheck `
                       -RunAction 'Preflight' -RunScope 'Pre-Flight Services' -RunMode 'Preflight'
            & $send @{ type='status'; text="Done. $($fan.Ok) ok, $($fan.Failed) failed of $($fan.Total)." }
            return @{ rows=$fan.Rows; summary=@{ total=$fan.Total; ok=$fan.Ok; failed=$fan.Failed } }
        }

        'kb-scan-findings' {
            # Extract Windows KB rollups referenced in each finding (plugin name +
            # solution text) -> one row per host x KB. Read-only; feeds the KB Installer.
            $paths = Get-AcasCsvPaths ([string]$Params['csvPaths'])
            $parsed = ConvertFrom-AcasCsv -Paths $paths -Text ([string]$Params['csvText']) -Send $send
            if ($parsed.Findings.Count -eq 0) { & $send @{ type='log'; level='warn'; text='No findings parsed.' }; return @{ rows=@(); summary=@{ total=0 } } }
            $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            $rows = New-Object System.Collections.ArrayList
            # KB rollups: "KB[ ]NNNNNN(NN)" or "(Apply )Security Update NNNNNN(NN)" -> normalize to KB<num>
            # (mirrors OG Get-NemKbParsedFindings: both patterns, 6-8 digits, optional space after KB).
            $kbRe = [regex]'(?i)\bKB\s*(\d{6,8})\b|(?:Apply\s+)?Security\s+Update\s+(\d{6,8})\b'
            $hostSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($f in $parsed.Findings) {
                $text = ([string]$f.PluginName) + ' ' + ([string]$f.Solution)
                $kbs = @($kbRe.Matches($text) | ForEach-Object {
                    $d = if ($_.Groups[1].Success) { $_.Groups[1].Value } else { $_.Groups[2].Value }
                    'KB' + $d
                } | Select-Object -Unique)
                if ($kbs.Count -eq 0) { continue }
                [void]$hostSet.Add([string]$f.Host)
                foreach ($kb in $kbs) {
                    $rk = ([string]$f.Host) + '|' + $kb
                    if ($seen.Contains($rk)) { continue }
                    [void]$seen.Add($rk)
                    $row = @{ Host=[string]$f.Host; KB=$kb; Severity=[string]$f.Severity; Plugin=[string]$f.PluginName; CVE=[string]$f.Cve; _rk=$rk }
                    [void]$rows.Add($row); & $send (@{ type='row' } + $row)
                }
            }
            & $send @{ type='status'; text="Found $($rows.Count) host x KB pair(s) across $($hostSet.Count) host(s)." }
            return @{ rows=@($rows); summary=@{ total=$rows.Count; hosts=$hostSet.Count } }
        }

        'kb-install' {
            $threads = 12; if ($Params['threads']) { [int]::TryParse([string]$Params['threads'], [ref]$threads) | Out-Null }
            $threads = [Math]::Max(1, [Math]::Min(32, $threads))
            $noReboot = $true; if ($Params.ContainsKey('noreboot') -and $null -ne $Params['noreboot']) { $noReboot = [bool]$Params['noreboot'] }
            $msuPath = ([string]$Params['msu']).Trim().Trim('"')
            $method  = if (([string]$Params['method']) -match '(?i)uso') { 'usoclient' } else { 'mecm' }
            # parse "host | KB1,KB2,..." lines into a per-host KB map
            $byHost = [ordered]@{}
            foreach ($line in (([string]$Params['pairs']) -split '[\r\n]+')) {
                $l = $line.Trim(); if (-not $l) { continue }
                $parts = $l -split '\|', 2; if ($parts.Count -lt 2) { continue }
                $h = Get-AcasShortHost ($parts[0].Trim()); if (-not $h) { continue }
                $kbs = @(($parts[1] -split '[,;\s]+') | ForEach-Object { $_.Trim().ToUpperInvariant() } | Where-Object { $_ } | ForEach-Object { if ($_ -notmatch '^KB') { "KB$_" } else { $_ } } | Select-Object -Unique)
                if ($kbs.Count -eq 0) { continue }
                if (-not $byHost.Contains($h)) { $byHost[$h] = New-Object System.Collections.Generic.List[string] }
                foreach ($kb in $kbs) { if (-not $byHost[$h].Contains($kb)) { $byHost[$h].Add($kb) } }
            }
            if ($byHost.Count -eq 0) { & $send @{ type='log'; level='warn'; text='No host|KB pairs to install.' }; return @{ rows=@(); summary=@{ total=0 } } }
            if ($msuPath -and -not (Test-Path -LiteralPath $msuPath)) { & $send @{ type='log'; level='warn'; text="MSU not found (MECM-only this run): $msuPath" } }
            & $send @{ type='log'; level='info'; text="KB install ($method) on $($byHost.Count) host(s)$(if($msuPath){" with MSU fallback $(Split-Path $msuPath -Leaf)"})$(if($noReboot){' [no-reboot]'})." }
            $jobs = New-Object System.Collections.ArrayList
            foreach ($h in $byHost.Keys) {
                $kbArr = @($byHost[$h])
                [void]$jobs.Add(@{ Host=$h; Args=@($h, $Credential, 'Negotiate', $kbArr, $msuPath, [bool]$noReboot, $method); Context=@{ KBs=($kbArr -join ',') } })
            }
            $rowOf = { param($res, $hostName, $ctxObj)
                @{ Host=$hostName; KBs=(Get-AcasMarker $res 'KBS'); MECM=[int](Get-AcasMarker $res 'MECM'); MSU=[int](Get-AcasMarker $res 'MSU'); Skipped=[int](Get-AcasMarker $res 'SKIP');
                   Result=$(if ($res -like 'FAIL*') { 'FAIL' } elseif ($res -like 'SKIP*') { 'SKIP' } else { 'OK' }); Detail=(Remove-AcasMarkers $res) } }
            $okOf  = $script:AcasOkOf
            $detOf = $script:AcasDetOfPlain
            $fan = Invoke-AcasFanOut -Jobs $jobs -Work $script:AcasKbInstallBlock -Threads $threads `
                       -RowOf $rowOf -OkOf $okOf -AuditAction 'VulnPatched' -AuditDetailOf $detOf -Send $send -CancelCheck $cancelCheck `
                       -RunAction 'KbInstall' -RunScope "KB install ($method): $($byHost.Count) host(s)" -RunMode $method
            & $send @{ type='status'; text="Done. $($fan.Ok) ok, $($fan.Failed) failed, $($fan.Skipped) skipped of $($fan.Total)." }
            return @{ rows=$fan.Rows; summary=@{ total=$fan.Total; ok=$fan.Ok; failed=$fan.Failed; skipped=$fan.Skipped; method=$method } }
        }

        'group-findings' {
            # Per-card drill-down: the finding rows behind one remediation card
            # (Host/Severity/Plugin/CVE/Solution), so the operator can review and
            # host-filter before patching. Re-parses; host arrays are never shipped
            # otherwise, so this is the on-demand path for the per-finding grid.
            $key = [string]$Params['key']
            if (-not $key) { & $send @{ type='log'; level='warn'; text='No group key.' }; return @{ rows=@(); summary=@{ total=0 } } }
            $paths = Get-AcasCsvPaths ([string]$Params['csvPaths'])
            $parsed = ConvertFrom-AcasCsv -Paths $paths -Text ([string]$Params['csvText']) -Send $send
            if ($parsed.Findings.Count -eq 0) { return @{ rows=@(); summary=@{ total=0 } } }
            $groups = @(Get-AcasRemediationGroups -Findings $parsed.Findings)
            $g = $groups | Where-Object { $_.Key -eq $key } | Select-Object -First 1
            if (-not $g) { & $send @{ type='log'; level='warn'; text="Group not found: $key" }; return @{ rows=@(); summary=@{ total=0 } } }
            $memberSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($mn in @($g.MemberNames)) { [void]$memberSet.Add([string]$mn) }
            $hostSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($hh in @($g.Hosts)) { [void]$hostSet.Add([string]$hh) }
            $rows = New-Object System.Collections.ArrayList
            $cap = 5000; $shown = 0; $matched = 0
            foreach ($f in $parsed.Findings) {
                if (-not $memberSet.Contains([string]$f.PluginName)) { continue }
                if (-not $hostSet.Contains([string]$f.Host)) { continue }
                $matched++
                if ($shown -ge $cap) { continue }
                $sol = [string]$f.Solution; if ($sol.Length -gt 400) { $sol = $sol.Substring(0,400) + '...' }
                $row = @{ Host=[string]$f.Host; Severity=[string]$f.Severity; Plugin=[string]$f.PluginName; CVE=[string]$f.Cve; Solution=$sol }
                [void]$rows.Add($row); & $send (@{ type='row' } + $row); $shown++
            }
            if ($matched -gt $cap) { & $send @{ type='log'; level='warn'; text="Showing first $cap of $matched finding(s) for this group." } }
            & $send @{ type='status'; text="$($g.DisplayName): $matched finding(s) across $($g.HostCount) host(s)." }
            return @{ rows=@($rows); summary=@{ total=$matched; shown=$shown; truncated=($matched -gt $cap); hostCount=$g.HostCount } }
        }

        { $_ -eq 'reboot-selected' -or $_ -eq 'verify-selected' } {
            # In-card Reboot actions: re-derive the group's host set by Key (the card
            # carries only a count) and dispatch the standard reboot / verify worker.
            $key = [string]$Params['key']
            if (-not $key) { & $send @{ type='log'; level='warn'; text='No group key.' }; return @{ rows=@(); summary=@{ total=0 } } }
            $paths = Get-AcasCsvPaths ([string]$Params['csvPaths'])
            $parsed = ConvertFrom-AcasCsv -Paths $paths -Text ([string]$Params['csvText']) -Send $send
            if ($parsed.Findings.Count -eq 0) { & $send @{ type='log'; level='warn'; text='No findings parsed.' }; return @{ rows=@(); summary=@{ total=0 } } }
            $groups = @(Get-AcasRemediationGroups -Findings $parsed.Findings)
            $g = $groups | Where-Object { $_.Key -eq $key } | Select-Object -First 1
            if (-not $g) { & $send @{ type='log'; level='warn'; text="Group not found: $key" }; return @{ rows=@(); summary=@{ total=0 } } }
            $targets = @($g.Hosts)
            if ($Params['hosts']) {
                $allow = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($hf in @($Params['hosts'])) { $sh = Get-AcasShortHost ([string]$hf); if ($sh) { [void]$allow.Add($sh) } }
                if ($allow.Count -gt 0) { $targets = @($g.Hosts | Where-Object { $allow.Contains($_) }) }
            }
            if ($targets.Count -eq 0) { & $send @{ type='log'; level='warn'; text='No targets for this group.' }; return @{ rows=@(); summary=@{ total=0 } } }
            $vulnDisplay = $g.DisplayName

            if ($ActionId -eq 'reboot-selected') {
                $warn = [string]$Params['warningText']
                if ([string]::IsNullOrWhiteSpace($warn)) { $warn = 'This workstation will reboot in 5 minutes for required security updates. Save your work now.' }
                & $send @{ type='status'; text="Scheduling reboot on $($targets.Count) host(s) for [$vulnDisplay]..." }
                $jobs = New-Object System.Collections.ArrayList
                foreach ($t in $targets) { [void]$jobs.Add(@{ Host=$t; Args=@($t, $warn, $Credential); Context=@{} }) }
                $rowOf = { param($res, $hostName, $ctx) @{ Host=$hostName; Result=$(if ($res -like 'FAIL*') { 'failed' } elseif ($res -match 'already') { 'already-pending' } else { 'scheduled' }); 'Exit Code'=(Get-AcasMarker $res 'EXIT'); Timestamp=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); Detail=(Remove-AcasMarkers $res) } }
                $okOf  = $script:AcasOkOf
                $detOf = $script:AcasDetOfPlain
                $fan = Invoke-AcasFanOut -Jobs $jobs -Work $script:AcasRebootWorker -Threads $threads `
                           -RowOf $rowOf -OkOf $okOf -AuditAction 'VulnPatched' -AuditDetailOf $detOf -Send $send -CancelCheck $cancelCheck `
                           -RunAction 'Reboot' -RunScope $vulnDisplay -RunMode 'Reboot'
                & $send @{ type='status'; text="Done. $($fan.Ok) ok, $($fan.Failed) failed of $($fan.Total)." }
                return @{ rows=$fan.Rows; summary=@{ total=$fan.Total; ok=$fan.Ok; failed=$fan.Failed } }
            } else {
                & $send @{ type='status'; text="Verifying post-reboot state on $($targets.Count) host(s) (up to 10min/host wait)..." }
                $jobs = New-Object System.Collections.ArrayList
                foreach ($t in $targets) { [void]$jobs.Add(@{ Host=$t; Args=@($t, $Credential); Context=@{} }) }
                $rowOf = { param($res, $hostName, $ctx) @{ Host=$hostName; Reachable=(Get-AcasMarker $res 'REACH'); RebootPending=(Get-AcasMarker $res 'PENDING'); 'OS Build'=(Get-AcasMarker $res 'BUILD'); Result=$(if ($res -like 'FAIL*') { 'FAIL' } else { 'OK' }); Timestamp=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); Detail=(Remove-AcasMarkers $res) } }
                $okOf  = $script:AcasOkOf
                $detOf = $script:AcasDetOfPlain
                # Reboot-verify waits up to 10 min/host: scale the batch deadline.
                $verifyDeadline = ([int][Math]::Ceiling($jobs.Count / [double][Math]::Max(1, $threads)) * 660) + 300
                $fan = Invoke-AcasFanOut -Jobs $jobs -Work $script:AcasRebootVerifyWorker -Threads $threads `
                           -RowOf $rowOf -OkOf $okOf -AuditAction 'TouchHost' -AuditDetailOf $detOf -Send $send -CancelCheck $cancelCheck `
                           -RunAction 'RebootVerify' -RunScope $vulnDisplay -RunMode 'Verify' -DeadlineSeconds $verifyDeadline
                & $send @{ type='status'; text="Done. $($fan.Ok) ok, $($fan.Failed) failed of $($fan.Total)." }
                return @{ rows=$fan.Rows; summary=@{ total=$fan.Total; ok=$fan.Ok; failed=$fan.Failed } }
            }
        }

        'list-profiles' {
            # Backbone reference: enumerate the remediation profile catalog with its
            # mechanism (Desc) + whether it auto-runs in the web host. Read-only.
            $rows = New-Object System.Collections.ArrayList
            foreach ($name in ($script:AcasUpdateProfiles.Keys | Sort-Object)) {
                $p = $script:AcasUpdateProfiles[$name]
                $type = 'Direct'
                if ($p.ContainsKey('IsPackage') -and $p.IsPackage) { $type = 'Package (PSADT)' }
                elseif ($p.ContainsKey('NeedsStaging') -and $p.NeedsStaging) { $type = 'Needs staging' }
                $auto = if (Test-AcasProfileAutoRunnable -ProfileName $name -StagingReady $log4j.Ready) { 'yes' } else { 'no' }
                $desc = if ($p.ContainsKey('Desc')) { [string]$p.Desc } else { '' }
                # NB: key must NOT be 'Type' - it collides (case-insensitively) with
                # the event's 'type' key when merged as @{ type='row' } + $row.
                $row = @{ Profile=$name; Mechanism=$desc; Kind=$type; 'Auto-Runnable'=$auto }
                [void]$rows.Add($row); & $send (@{ type='row' } + $row)
            }
            & $send @{ type='status'; text="$($rows.Count) remediation profile(s)." }
            return @{ rows=@($rows); profiles=@($rows); summary=@{ total=$rows.Count } }
        }

        'findings-for-host' {
            # Cross-reference one host to its findings (Plugin/Severity/CVE/Solution).
            $hostQ = Get-AcasShortHost ([string]$Params['host'])
            if (-not $hostQ) { & $send @{ type='log'; level='warn'; text='Host is required.' }; return @{ rows=@(); summary=@{ total=0 } } }
            $paths = Get-AcasCsvPaths ([string]$Params['csvPaths'])
            $parsed = ConvertFrom-AcasCsv -Paths $paths -Text ([string]$Params['csvText']) -Send $send
            if ($parsed.Findings.Count -eq 0) { return @{ rows=@(); summary=@{ total=0 } } }
            $rows = New-Object System.Collections.ArrayList
            foreach ($f in $parsed.Findings) {
                if ([string]$f.Host -ne $hostQ) { continue }
                $sol = [string]$f.Solution; if ($sol.Length -gt 400) { $sol = $sol.Substring(0,400) + '...' }
                $row = @{ Host=$hostQ; Severity=[string]$f.Severity; Plugin=[string]$f.PluginName; CVE=[string]$f.Cve; Solution=$sol }
                [void]$rows.Add($row); & $send (@{ type='row' } + $row)
            }
            & $send @{ type='status'; text="$hostQ : $($rows.Count) finding(s)." }
            return @{ rows=@($rows); summary=@{ total=$rows.Count } }
        }

        default {
            & $send @{ type='error'; text="Unknown action '$ActionId'." }
            return @{ rows=@(); summary=@{} }
        }
    }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction
