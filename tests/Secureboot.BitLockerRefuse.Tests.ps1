# =============================================================================
#  Secureboot.BitLockerRefuse.Tests.ps1 - Pester 3.4 for the audit 2026-07-24
#  secureboot fix pass and its 2026-07-25 fable re-audit follow-up (v1.6.9).
#
#  P1 - THE FLEET-STRANDING ONE. The enable path never touched BitLocker: not a
#  single BitLocker/TPM reference existed in the module. Turning Secure Boot on
#  re-measures the boot PCRs the TPM seals the BitLocker volume master key to,
#  so on the pending reboot EVERY TPM-protected host stops at the 48-digit
#  recovery-key prompt - and a user without their key cannot boot at all. The
#  payload now suspends BitLocker for exactly ONE reboot on every TPM-sealed
#  volume before the firmware write, and FAILS CLOSED: a host whose suspend
#  does not take is REFUSED, never written.
#
#  P3 - a brick-safety refusal (UEFI+GPT could not be confirmed) used to ride
#  out as Skipped/$true, so it was tallied as "already enabled" and painted
#  green. Refusals now carry a distinct 'Refused' status, tally and colour.
#
#  P5 - secureboot was the only module reading a 'confirm' param it never
#  declared in its manifest.
#
#  audit 2026-07-25 (fable re-audit follow-up) - the fail-closed guarantee had one
#  fail-OPEN corner: the cmdlets-absent manage-bde fallback proceeded on a throw,
#  a non-zero exit, empty output or LOCALIZED output. It now refuses anything it
#  cannot positively parse as protection-off. And the suspend runs BEFORE the
#  manufacturer switch, so a host whose write never happened (unsupported OEM /
#  rejected write) is now RESUMED instead of eating an unprotected boot for nothing.
#
#  These are BEHAVIOURAL where they can be: the payload is a here-string that
#  runs on the REMOTE box, so it is executed here inside a mocked scope (the
#  FixVerify3 pattern) rather than only pattern-matched. The one thing that
#  cannot be mocked is $env:firmware_type (a PS 5.1 runspace pins that name once
#  it has resolved it), so the payload runs are done on a UEFI host and the
#  firmware half of the brick-safety gate is asserted by text instead.
#
#  Run:  Invoke-Pester -Path .\tests\Secureboot.BitLockerRefuse.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.secureboot.psm1') -Force -PassThru
$script:Src  = Get-Content (Join-Path $script:Root 'modules\JanetWeb.secureboot.psm1') -Raw
$script:View = Get-Content (Join-Path $script:Root 'web\js\views\secureboot.view.js') -Raw
$script:Payload = & $script:Mod { $script:SbePayload }

# Run the REAL SYSTEM payload in a scope where the firmware/disk/BitLocker
# cmdlets it calls are replaced by mocks, and hand back the JSON it wrote.
# $PSCommandPath is nulled so the payload's own self-delete cannot touch a
# test file, and $env:firmware_type is set/restored around the run.
function Invoke-SbePayloadForTest {
    param([string]$MockText, [string]$Mfr = 'Dell Inc.', [string]$Firmware = 'UEFI', [string]$Partition = 'GPT')
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('sbe_' + [guid]::NewGuid().ToString('N') + '.json')
    $oldFw = $env:firmware_type
    $env:firmware_type = $Firmware
    $global:__sbeWmiCalls = 0
    $global:__blResumed   = @()   # audit 2026-07-25: mount points Resume-BitLocker was called on
    try {
        $runner = [scriptblock]::Create(@"
param(`$src, `$ResultPath)
`$PSCommandPath = `$null
`$BIOSPassword  = 'x'
function Get-CimInstance { [CmdletBinding()] param(`$ClassName, `$Namespace) [pscustomobject]@{ Manufacturer = '$Mfr' } }
function Confirm-SecureBootUEFI { [CmdletBinding()] param() `$false }
function Get-Disk { [CmdletBinding()] param() [pscustomobject]@{ IsBoot = `$true; IsSystem = `$true; PartitionStyle = '$Partition' } }
# Any OEM branch reaching for the BIOS provider means a firmware write was attempted.
function Get-WmiObject { [CmdletBinding()] param(`$Class, `$Namespace) `$global:__sbeWmiCalls++; throw 'BIOS write attempted' }
$MockText
Invoke-Expression `$src
"@)
        & $runner $script:Payload $tmp
        return (Get-Content -LiteralPath $tmp -Raw | ConvertFrom-Json)
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        $env:firmware_type = $oldFw
    }
}

# A TPM-sealed C: whose suspend hard-fails.
$script:MockSuspendFails = @'
function Get-BitLockerVolume { [CmdletBinding()] param($MountPoint)
    [pscustomobject]@{ MountPoint = 'C:'; ProtectionStatus = 'On'; KeyProtector = @([pscustomobject]@{ KeyProtectorType = 'Tpm' }) }
}
function Suspend-BitLocker { [CmdletBinding()] param($MountPoint, $RebootCount) throw 'Access is denied' }
'@

# A TPM-sealed C: whose suspend takes (protection reads Off on the verify pass).
$script:MockSuspendWorks = @'
function Get-BitLockerVolume { [CmdletBinding()] param($MountPoint)
    if ($MountPoint) { [pscustomobject]@{ MountPoint = 'C:'; ProtectionStatus = $global:__blState; KeyProtector = @() } }
    else { [pscustomobject]@{ MountPoint = 'C:'; ProtectionStatus = 'On'; KeyProtector = @([pscustomobject]@{ KeyProtectorType = 'Tpm' }) } }
}
function Suspend-BitLocker { [CmdletBinding()] param($MountPoint, $RebootCount)
    $global:__blReboot = $RebootCount
    $global:__blState  = 'Off'
}
'@

# A TPM-sealed C: whose suspend silently no-ops (protection still On afterwards).
$script:MockSuspendNoOps = @'
function Get-BitLockerVolume { [CmdletBinding()] param($MountPoint)
    [pscustomobject]@{ MountPoint = 'C:'; ProtectionStatus = 'On'; KeyProtector = @([pscustomobject]@{ KeyProtectorType = 'Tpm' }) }
}
function Suspend-BitLocker { [CmdletBinding()] param($MountPoint, $RebootCount) }
'@

# Encrypted but NOT TPM-sealed (recovery-password only) - no PCR seal, nothing to suspend.
$script:MockNoTpmProtector = @'
function Get-BitLockerVolume { [CmdletBinding()] param($MountPoint)
    [pscustomobject]@{ MountPoint = 'C:'; ProtectionStatus = 'On'; KeyProtector = @([pscustomobject]@{ KeyProtectorType = 'RecoveryPassword' }) }
}
function Suspend-BitLocker { [CmdletBinding()] param($MountPoint, $RebootCount) throw 'must not be called' }
'@

# =============================================================================
#  audit 2026-07-25 (fable re-audit follow-up) - the CMDLETS-ABSENT fallback.
#
#  Composes a mock scope where the BitLocker cmdlets do NOT exist (Get-Command
#  returns nothing for them) and manage-bde behaves however the case needs. The
#  payload builds its manage-bde path with Join-Path and gate-checks it with
#  Test-Path, then invokes it through the call operator - so shadowing those two
#  and naming the shim '__sbeMbde' is enough to drive the whole branch. The shim
#  is declared WITHOUT a param block on purpose: `& '__sbeMbde' -status` then
#  parks '-status' in $args instead of failing parameter binding.
#  $LASTEXITCODE is set explicitly by each shim because a FUNCTION never sets it.
# =============================================================================
function New-MbdeMock {
    # -Body is inserted VERBATIM (one expansion, never re-parsed), so pass it as a
    # SINGLE-quoted string: its `n / $global: survive to the generated source and are
    # interpreted there, not here.
    param([string]$Body, [bool]$MbdePresent = $true)
    $present = if ($MbdePresent) { '$true' } else { '$false' }
    @"
function Get-Command { [CmdletBinding()] param([Parameter(Position=0)]`$Name) `$null }
function Join-Path   { [CmdletBinding()] param([Parameter(Position=0)]`$Path, [Parameter(Position=1)]`$ChildPath) '__sbeMbde' }
function Test-Path   { [CmdletBinding()] param([Parameter(Position=0)]`$Path, `$LiteralPath) $present }
function __sbeMbde { $Body }
"@
}

$script:MockMbdeThrows      = New-MbdeMock -Body 'throw "manage-bde: access is denied"'
$script:MockMbdeEmpty       = New-MbdeMock -Body '$global:LASTEXITCODE = 0; ""'
$script:MockMbdeNonZeroExit = New-MbdeMock -Body '$global:LASTEXITCODE = 2; "ERROR: An error occurred (code 0x80070005)."'
# German manage-bde: real output, but none of the English tokens the old regex needed.
$script:MockMbdeLocalized   = New-MbdeMock -Body '$global:LASTEXITCODE = 0; "Volume C: [OSDisk]`n    Schutzstatus:    Der Schutz ist aktiviert`n"'
$script:MockMbdeProtectedOn = New-MbdeMock -Body '$global:LASTEXITCODE = 0; "Volume C: [OSDisk]`n    Conversion Status:    Fully Encrypted`n    Protection Status:    Protection On`n"'
$script:MockMbdeAllOff      = New-MbdeMock -Body '$global:LASTEXITCODE = 0; "Volume C: [OSDisk]`n    Conversion Status:    Fully Decrypted`n    Protection Status:    Protection Off`n"'
$script:MockMbdeAbsent      = New-MbdeMock -Body 'throw "must not be called"' -MbdePresent $false

# A TPM-sealed C: whose suspend takes, plus a Resume-BitLocker that RECORDS the
# resume. Used to prove BitLocker is put back when no firmware write happened.
$script:MockSuspendWorksWithResume = @'
function Get-BitLockerVolume { [CmdletBinding()] param($MountPoint)
    if ($MountPoint) { [pscustomobject]@{ MountPoint = 'C:'; ProtectionStatus = $global:__blState; KeyProtector = @() } }
    else { [pscustomobject]@{ MountPoint = 'C:'; ProtectionStatus = 'On'; KeyProtector = @([pscustomobject]@{ KeyProtectorType = 'Tpm' }) } }
}
function Suspend-BitLocker { [CmdletBinding()] param($MountPoint, $RebootCount)
    $global:__blReboot = $RebootCount
    $global:__blState  = 'Off'
}
function Resume-BitLocker { [CmdletBinding()] param($MountPoint)
    $global:__blResumed += @("$MountPoint")
    $global:__blState = 'On'
}
'@

# ...plus a Dell BIOS provider that REJECTS the write (Status 5 = wrong/absent
# BIOS admin password). The firmware is untouched, so the suspend bought nothing.
$script:MockDellRejects = $script:MockSuspendWorksWithResume + @'

function Get-CimInstance { [CmdletBinding()] param([Parameter(Position=0)]$ClassName, $Namespace)
    if ("$ClassName" -eq 'Win32_ComputerSystem') { return [pscustomobject]@{ Manufacturer = 'Dell Inc.' } }
    [pscustomobject]@{ AttributeName = 'SecureBoot'; CurrentValue = 'Disabled' }
}
function Get-WmiObject { [CmdletBinding()] param($Class, $Namespace)
    $global:__sbeWmiCalls++
    $o = New-Object psobject
    $o | Add-Member -MemberType ScriptMethod -Name SetAttribute -Value { param($a, $b, $c, $d, $e) [pscustomobject]@{ Status = 5 } } -PassThru
}
'@

# ...and a Dell that is ALREADY staged pending-reboot (AlreadyPending). No write
# is fired, but the NEXT boot is the re-measured one - so the suspend must STAY.
$script:MockDellAlreadyPending = $script:MockSuspendWorksWithResume + @'

function Get-CimInstance { [CmdletBinding()] param([Parameter(Position=0)]$ClassName, $Namespace)
    if ("$ClassName" -eq 'Win32_ComputerSystem') { return [pscustomobject]@{ Manufacturer = 'Dell Inc.' } }
    [pscustomobject]@{ AttributeName = 'SecureBoot'; CurrentValue = 'Enabled' }
}
'@

# ...and a Dell that ACCEPTS the write (Status 0 = staged for the next boot). That
# boot IS the re-measured one, so the suspend must stay in place here too.
$script:MockDellAccepts = $script:MockSuspendWorksWithResume + @'

function Get-CimInstance { [CmdletBinding()] param([Parameter(Position=0)]$ClassName, $Namespace)
    if ("$ClassName" -eq 'Win32_ComputerSystem') { return [pscustomobject]@{ Manufacturer = 'Dell Inc.' } }
    [pscustomobject]@{ AttributeName = 'SecureBoot'; CurrentValue = 'Disabled' }
}
function Get-WmiObject { [CmdletBinding()] param($Class, $Namespace)
    $global:__sbeWmiCalls++
    $o = New-Object psobject
    $o | Add-Member -MemberType ScriptMethod -Name SetAttribute -Value { param($a, $b, $c, $d, $e) [pscustomobject]@{ Status = 0 } } -PassThru
}
'@

Describe 'secureboot 1.6.9 - manifest pin + the confirm input it always read (audit 2026-07-24 P5)' {
    $man = & $script:Mod { Get-JanetToolManifest }
    $en  = @($man.actions | Where-Object { $_.id -eq 'enable-secure-boot' })[0]

    It 'manifest version is exactly 1.6.9 (newest bump = audit 2026-07-25 fable re-audit follow-up; exact pin lives here)' {
        [string]$man.version | Should Be '1.6.9'
    }
    It 'enable-secure-boot DECLARES the confirm input the module enforces server-side' {
        # The gate at Invoke-JanetToolAction reads $Params['confirm'] - undeclared, it was
        # invisible to the manifest-driven generic view and to any API caller reading inputs.
        $cf = @($en.inputs | Where-Object { $_.name -eq 'confirm' })
        $cf.Count | Should Be 1
        ([string]$cf[0].type) | Should Be 'text'
        ([string]$cf[0].label -cmatch 'ENABLE') | Should Be $true
    }
    It 'the confirm input is NOT required (dry run is deliberately ungated)' {
        $cf = @($en.inputs | Where-Object { $_.name -eq 'confirm' })[0]
        [bool]$cf.required | Should Be $false
    }
    It 'the declared input name matches the param the module actually reads, case-exactly' {
        # audit 2026-07-24 (fable re-audit F3): -cne, not -ne. A case-INSENSITIVE gate accepted
        # 'enable' on a fleet FIRMWARE WRITE while its own error text promised "exactly".
        ($script:Src -match "\[string\]\`$Params\['confirm'\] -cne 'ENABLE'") | Should Be $true
    }
    It 'the BitLocker column is declared so the per-host suspend outcome is reportable' {
        (@($en.columns) -contains 'BitLocker') | Should Be $true
    }
}

Describe 'secureboot 1.6.9 - payload SUSPENDS BitLocker before the firmware write (audit 2026-07-24 P1)' {

    # --- text assertions: the payload is a here-string shipped to the remote box ---
    It 'the remote payload contains the one-reboot BitLocker suspend' {
        ($script:Payload -match 'Suspend-BitLocker\s+-MountPoint\s+\$mp\s+-RebootCount\s+1') | Should Be $true
    }
    It 'the remote payload contains the FAIL-CLOSED branch (no write when the suspend fails)' {
        ($script:Payload -match '\$bl\s*=\s*Suspend-TpmBitLockerForFirmware')       | Should Be $true
        ($script:Payload -match 'if\s*\(-not\s+\$bl\.Ok\)')                          | Should Be $true
        ($script:Payload -match "BitLocker safety stop")                             | Should Be $true
        ($script:Payload -match 'Refused      = \$true')                             | Should Be $true
    }
    It 'the OEM write switch sits in the ELSE of the BitLocker gate (unreachable when it fails)' {
        $idxGate   = $script:Payload.IndexOf('if (-not $bl.Ok)')
        $idxSwitch = $script:Payload.IndexOf('$out = switch -Regex ($mfr)')
        ($idxGate -ge 0)          | Should Be $true
        ($idxSwitch -gt $idxGate) | Should Be $true
    }
    It 'only TPM-BACKED protectors are treated as PCR-sealed' {
        ($script:Payload -match "\`$tpmTypes\s*=\s*@\('Tpm','TpmPin','TpmStartupKey','TpmPinStartupKey'\)") | Should Be $true
    }

    # --- behavioural: run the real payload against mocked cmdlets ---
    It 'a FAILED suspend REFUSES the host and attempts NO BIOS write' {
        $obj = Invoke-SbePayloadForTest -MockText $script:MockSuspendFails -Mfr 'Dell Inc.'
        [string]$obj.SetResult | Should Be 'Refused'
        [bool]$obj.Refused     | Should Be $true
        [bool]$obj.Skipped     | Should Be $false
        $obj.Error             | Should Match 'BitLocker safety stop'
        $obj.Error             | Should Match 'recovery-key prompt'
        $obj.BitLocker         | Should Match 'NOT SUSPENDED'
        $global:__sbeWmiCalls  | Should Be 0     # <-- the fix: firmware was never touched
    }
    It 'a suspend that silently NO-OPS (protection still On) also refuses' {
        $obj = Invoke-SbePayloadForTest -MockText $script:MockSuspendNoOps -Mfr 'Dell Inc.'
        [string]$obj.SetResult | Should Be 'Refused'
        $obj.Error             | Should Match 'still ON'
        $global:__sbeWmiCalls  | Should Be 0
    }
    It 'a SUCCESSFUL suspend uses RebootCount 1, proceeds to the OEM branch, and reports the volume' {
        $global:__blState  = 'On'
        $global:__blReboot = -1
        # 'Contoso' takes the switch default (New-Result, no BIOS provider call) so this
        # asserts the gate OPENED without needing a full OEM WMI fake.
        $obj = Invoke-SbePayloadForTest -MockText $script:MockSuspendWorks -Mfr 'Contoso'
        $global:__blReboot     | Should Be 1     # suspended for exactly ONE reboot, not indefinitely
        [string]$obj.SetResult | Should Be 'N/A'
        $obj.Error             | Should Match 'Unsupported manufacturer'
        $obj.BitLocker         | Should Match 'Suspended for 1 reboot'
        $obj.BitLocker         | Should Match 'C:'
    }
    It 'a volume with NO TPM protector is left alone (not PCR-sealed) and the run proceeds' {
        $obj = Invoke-SbePayloadForTest -MockText $script:MockNoTpmProtector -Mfr 'Contoso'
        [string]$obj.SetResult | Should Be 'N/A'
        $obj.BitLocker         | Should Match 'No TPM-sealed BitLocker volume'
    }
}

Describe 'secureboot 1.6.9 - a safety REFUSAL is not a success (audit 2026-07-24 P3)' {

    # Driven through the DISK half of the gate: the firmware half reads $env:firmware_type,
    # and a PS 5.1 runspace will not re-read that name once it has resolved it, so it cannot
    # be flipped in-process. Both halves set the SAME $bootSafe/$out refusal block (asserted
    # by text below), so the disk path exercises the behaviour end to end.
    It 'the brick-safety stop now emits Refused, not Skipped (it was tallied as already-enabled)' {
        $obj = Invoke-SbePayloadForTest -MockText $script:MockSuspendWorks -Mfr 'Dell Inc.' -Partition 'MBR'
        [string]$obj.SetResult | Should Be 'Refused'
        [bool]$obj.Refused     | Should Be $true
        [bool]$obj.Skipped     | Should Be $false   # <-- was $true: green + counted as enabled
        $obj.Error             | Should Match 'Brick-safety stop'
        $obj.Error             | Should Match 'not GPT'
        $global:__sbeWmiCalls  | Should Be 0
    }
    It 'the firmware half of the gate feeds the same single refusal block' {
        ($script:Payload -match "\`$bootSafe = \`$false; \`$bootWhy = \""firmware_type='\`$fw' \(OS not booted in UEFI mode\)\""") | Should Be $true
        # exactly one brick-safety $out object, and it is the Refused one
        (([regex]::Matches($script:Payload, 'Brick-safety stop:')).Count) | Should Be 1
    }

    Context 'the live worker resolves Refused to its own status' {
        # The REAL mapping, lifted from the live worker by AST (FixVerify3's pattern).
        $lw = & $script:Mod { $script:SbeLiveWorker }
        $assign = $lw.Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                                    $n.Left.Extent.Text -eq '$resolvedStatus' }, $true) | Select-Object -First 1
        $mapper = [scriptblock]::Create("param(`$result) $($assign.Extent.Text); `$resolvedStatus")

        It 'Refused flag => Refused (NOT Skipped, NOT Error)' {
            (& $mapper ([pscustomobject]@{ Unknown=$false; Refused=$true; Skipped=$false; Error='Brick-safety stop: ...' })) | Should Be 'Refused'
        }
        It 'the existing outcomes are unchanged' {
            (& $mapper ([pscustomobject]@{ Unknown=$true;  Refused=$false; Skipped=$false; Error='x'  })) | Should Be 'Unknown'
            (& $mapper ([pscustomobject]@{ Unknown=$false; Refused=$false; Skipped=$true;  Error=''   })) | Should Be 'Skipped'
            (& $mapper ([pscustomobject]@{ Unknown=$false; Refused=$false; Skipped=$false; Error=''   })) | Should Be 'Success'
            (& $mapper ([pscustomobject]@{ Unknown=$false; Refused=$false; Skipped=$false; Error='boom' })) | Should Be 'Error'
        }
    }

    It 'the enable harvest gives Refused its own tally, out of the already-enabled bucket' {
        ($script:Src -match '\$isRefused\s*=\s*\(\$status\s*-eq\s*''Refused''\)')     | Should Be $true
        ($script:Src -match 'elseif \(\$isRefused\) \{ \$refusedCount\+\+ \}')        | Should Be $true
        ($script:Src -match 'refused=\$refusedCount')                                 | Should Be $true
    }
    It 'a Refused host is audited Skipped/itemCount 0 - never Success, never Failure' {
        ($script:Src -match "if \(\`$isOk\) \{ 'Success' \} elseif \(\`$isSkip -or \`$isUnknown -or \`$isRefused\) \{ 'Skipped' \}") | Should Be $true
    }
    It 'the view paints Refused amber and counts it separately (it rendered green + invisible)' {
        ($script:View -match "case 'Refused': return 'st-warn';")                      | Should Be $true
        ($script:View -match "s === 'Timeout' \|\| s === 'Refused'\) return 'row-warn'") | Should Be $true
        ($script:View -match 'Success: 0, Skipped: 0, Unknown: 0, Refused: 0')                     | Should Be $true
        ($script:View.IndexOf("c.Refused + ' refused, '") -ge 0)                       | Should Be $true
    }
    It 'the view surfaces the per-host BitLocker outcome as its own column' {
        ($script:View -match "key: 'BitLocker', label: 'BITLOCKER'") | Should Be $true
        ($script:View -match "\['BitLocker', 'BitLocker'\]")         | Should Be $true
    }
    It 'the arming dialog no longer claims BitLocker is left alone' {
        ($script:View.IndexOf('BitLocker is NOT suspended by this tool') -lt 0) | Should Be $true
        ($script:View -match 'BitLocker is suspended for one reboot')           | Should Be $true
    }
}

Describe 'secureboot 1.6.9 - post-run C$ diagnosis + Dry Run tooltip (audit 2026-07-24 P3/P4)' {
    It 'C$ reachability is sampled while the credentialed PSDrive is still mounted' {
        # Probing after Remove-PSDrive re-authenticated as the SERVER process, so a real
        # timeout came back as "permission denied" and sent the operator after ACLs.
        ($script:Src -match '\$shareReachable\s*=\s*\$null')                                  | Should Be $true
        $idxProbe = $script:Src.IndexOf('$shareReachable = [bool](Test-Path')
        ($idxProbe -ge 0) | Should Be $true
        # the sample must come BEFORE the drive is dropped in the same finally block
        ($idxProbe -lt $script:Src.IndexOf('$shareOk = if ($null -ne $shareReachable)')) | Should Be $true
    }
    It 'the diagnosis consumes the mounted-drive reading instead of re-probing bare' {
        ($script:Src -match '\$shareOk = if \(\$null -ne \$shareReachable\)') | Should Be $true
        ($script:Src -match 'if \(-not \$shareOk\) \{')                       | Should Be $true
    }
    It 'the Dry Run tooltip no longer advertises DCOM, which the worker refuses to use' {
        $idxDry = $script:View.IndexOf("Dry Run - connectivity + manufacturer detection only");
        ($idxDry -ge 0) | Should Be $true
        ($script:View -match "title: 'Probe TCP reachability \(5985/5986/445\) \+ manufacturer over WinRM - never DCOM") | Should Be $true
        ($script:View.IndexOf('manufacturer via DCOM only') -lt 0) | Should Be $true
    }
}

# =============================================================================
#  audit 2026-07-25 (fable re-audit follow-up)
# =============================================================================

Describe 'secureboot 1.6.9 - the cmdlets-absent manage-bde fallback FAILS CLOSED (audit 2026-07-25 P3)' {
    # The re-audit proved this corner fail-OPEN: with the BitLocker cmdlets absent and
    # manage-bde present-but-throwing, Ok came back $true with a Detail asserting "no
    # protected volume to suspend" - and the firmware write then proceeded on a host
    # whose BitLocker state was never actually read. Every case below is driven through
    # the REAL payload with -Mfr 'Dell Inc.', so a regression to fail-open reaches the
    # Dell BIOS provider and trips the WMI counter.

    It 'manage-bde THROWING refuses the host and attempts NO BIOS write' {
        $obj = Invoke-SbePayloadForTest -MockText $script:MockMbdeThrows -Mfr 'Dell Inc.'
        [string]$obj.SetResult | Should Be 'Refused'
        [bool]$obj.Refused     | Should Be $true
        [bool]$obj.Skipped     | Should Be $false
        $obj.Error             | Should Match 'BitLocker safety stop'
        $obj.Error             | Should Match 'could not be determined'
        $obj.BitLocker         | Should Match 'NOT SUSPENDED'
        $global:__sbeWmiCalls  | Should Be 0
    }
    It 'EMPTY manage-bde output refuses (it never said "off" - it said nothing)' {
        $obj = Invoke-SbePayloadForTest -MockText $script:MockMbdeEmpty -Mfr 'Dell Inc.'
        [string]$obj.SetResult | Should Be 'Refused'
        $obj.Error             | Should Match 'could not be determined'
        $global:__sbeWmiCalls  | Should Be 0
    }
    It 'a NON-ZERO manage-bde exit code refuses' {
        $obj = Invoke-SbePayloadForTest -MockText $script:MockMbdeNonZeroExit -Mfr 'Dell Inc.'
        [string]$obj.SetResult | Should Be 'Refused'
        $obj.Error             | Should Match 'could not be determined'
        $global:__sbeWmiCalls  | Should Be 0
    }
    It 'LOCALIZED manage-bde output refuses (the old regex only knew English)' {
        # German 'Schutzstatus: Der Schutz ist aktiviert' IS protection ON, and the old
        # English-only regex read it as "not on" and wrote firmware anyway.
        $obj = Invoke-SbePayloadForTest -MockText $script:MockMbdeLocalized -Mfr 'Dell Inc.'
        [string]$obj.SetResult | Should Be 'Refused'
        $obj.Error             | Should Match 'localized'
        $global:__sbeWmiCalls  | Should Be 0
    }
    It 'manage-bde reporting Protection On still refuses (unchanged)' {
        $obj = Invoke-SbePayloadForTest -MockText $script:MockMbdeProtectedOn -Mfr 'Dell Inc.'
        [string]$obj.SetResult | Should Be 'Refused'
        $obj.Error             | Should Match 'protection is ON'
        $global:__sbeWmiCalls  | Should Be 0
    }
    It 'ONLY a positively-parsed "every volume Protection Off" may proceed' {
        $obj = Invoke-SbePayloadForTest -MockText $script:MockMbdeAllOff -Mfr 'Contoso'
        [string]$obj.SetResult | Should Be 'N/A'          # reached the OEM switch
        [bool]$obj.Refused     | Should Be $false
        $obj.Error             | Should Match 'Unsupported manufacturer'
        $obj.BitLocker         | Should Match 'Protection Off'
    }
    It 'cmdlets AND manage-bde both absent proceeds - the feature is genuinely not installed' {
        $obj = Invoke-SbePayloadForTest -MockText $script:MockMbdeAbsent -Mfr 'Contoso'
        [string]$obj.SetResult | Should Be 'N/A'
        [bool]$obj.Refused     | Should Be $false
        $obj.BitLocker         | Should Match 'both absent'
    }
    It 'the honest Detail never claims "no protected volume" for an UNREAD state' {
        # The old string asserted a fact about the host that had never been established.
        ($script:Payload.IndexOf('BitLocker cmdlets not present; no protected volume to suspend.') -lt 0) | Should Be $true
    }
}

Describe 'secureboot 1.6.9 - BitLocker is RESUMED when the firmware write never happened (audit 2026-07-25 P3)' {
    # The suspend runs BEFORE the manufacturer switch, so an unsupported OEM or a
    # rejected OEM write left the host suspended for its next reboot with ZERO firmware
    # change to show for it - a needless unprotected boot.

    It 'an UNSUPPORTED OEM resumes the volume it suspended for nothing' {
        $global:__blState = 'On'
        $obj = Invoke-SbePayloadForTest -MockText $script:MockSuspendWorksWithResume -Mfr 'Contoso'
        $obj.Error                         | Should Match 'Unsupported manufacturer'
        (@($global:__blResumed) -join ',') | Should Be 'C:'
        $obj.BitLocker                     | Should Match 'Suspended for 1 reboot'
        $obj.BitLocker                     | Should Match 'RESUMED'
    }
    It 'a REJECTED Dell write (bad BIOS password) resumes too' {
        $global:__blState = 'On'
        $obj = Invoke-SbePayloadForTest -MockText $script:MockDellRejects -Mfr 'Dell Inc.'
        $obj.Error                         | Should Match 'Dell BIOS write rejected'
        $global:__sbeWmiCalls              | Should Be 1     # the write WAS attempted - and refused
        (@($global:__blResumed) -join ',') | Should Be 'C:'
        $obj.BitLocker                     | Should Match 'RESUMED'
    }
    It 'AlreadyPending does NOT resume - that host needs the suspend for its re-measured boot' {
        $global:__blState = 'On'
        $obj = Invoke-SbePayloadForTest -MockText $script:MockDellAlreadyPending -Mfr 'Dell Inc.'
        [string]$obj.SetResult                    | Should Be 'AlreadyPending'
        @($global:__blResumed).Count              | Should Be 0
        $obj.BitLocker                            | Should Match 'Suspended for 1 reboot'
        ([string]$obj.BitLocker -match 'RESUMED') | Should Be $false
    }
    It 'an ACCEPTED write does NOT resume - the pending boot is the re-measured one' {
        $global:__blState = 'On'
        $obj = Invoke-SbePayloadForTest -MockText $script:MockDellAccepts -Mfr 'Dell Inc.'
        [string]$obj.Error                        | Should Be ''
        @($global:__blResumed).Count              | Should Be 0
        ([string]$obj.BitLocker -match 'RESUMED') | Should Be $false
    }
    It 'a refusal that never suspended anything has nothing to resume' {
        $obj = Invoke-SbePayloadForTest -MockText $script:MockSuspendFails -Mfr 'Dell Inc.'
        [string]$obj.SetResult       | Should Be 'Refused'
        @($global:__blResumed).Count | Should Be 0
    }
}

Describe 'secureboot 1.6.9 - row-shape + view consistency (audit 2026-07-25 P4)' {
    It 'every "?" row shape (early error / corrupt / C$ denied / timeout / worker / cancel) carries a BitLocker cell' {
        # A missing key left a blank cell in the new BITLOCKER column on exactly the rows
        # an operator scans hardest.
        (([regex]::Matches($script:Src, "SetResult='\?'; BitLocker='n/a'")).Count) | Should Be 8
        # ...and not one of them is left without it.
        ($script:Src -match "SetResult='\?'; (Error|Hint)=") | Should Be $false
    }
    It 'the view summarize() has an Unknown bucket so the counts sum to Total' {
        # 'Unknown' (Confirm-SecureBootUEFI unreadable, no write attempted) is a live status
        # the worker emits; with no bucket it appeared in NO completion-dialog count.
        ($script:View -match 'var c = \{ Success: 0, Skipped: 0, Unknown: 0, Refused: 0, Error: 0, Timeout: 0, DryRun: 0 \};') | Should Be $true
        ($script:View.IndexOf('(c.Skipped + c.Unknown)') -ge 0)            | Should Be $true
        ($script:View -match 'Unknown \(state unreadable - not written\)') | Should Be $true
    }
}
