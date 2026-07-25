# =============================================================================
#  Secureboot.ScanEnableParity.Tests.ps1 - Pester 3.4 for the audit 2026-07-25
#  capability-audit item #3 (v1.7.0): SECURE BOOT PRE-FLIGHT PARITY.
#
#  THE GAP THIS PINS SHUT
#  ----------------------
#  v1.6.9 hardened the ENABLE path to REFUSE any host whose BitLocker state it
#  cannot positively read, or that is protected and cannot be suspended. But the
#  READ-ONLY scan carried no BitLocker column at all - it weighed only Secure Boot
#  state / firmware / disk / OEM - so it printed READY TO ENABLE for hosts the
#  enable path would Refuse at firmware-write time. The operator discovered that
#  only after arming a destructive fleet wave.
#
#  The fix is not "add the same checks to the scan". Two implementations of one
#  rule is the defect class this repo keeps paying for. There is now exactly ONE:
#  Get-SbeBitLockerPosture, whose SOURCE ($script:SbeBitLockerPostureSrc) is
#  prepended verbatim to the SYSTEM payload AND dot-sourced into the scan's remote
#  probe. Suspend-TpmBitLockerForFirmware keeps only the WRITE half.
#
#  WHAT THIS FILE PROVES
#  ---------------------
#   1. STRUCTURAL - the enable path holds no detection logic of its own, so it
#      cannot drift from the scan even in principle (AST over the real payload).
#   2. BEHAVIOURAL - for every BitLocker state in the suite, the REAL payload is
#      run under mocks and the REAL posture helper is run under the SAME mocks;
#      any state the payload Refuses is never scored READY TO ENABLE by the scan.
#   3. READ-ONLY - nothing on the scan path can suspend, resume or write BitLocker.
#   4. FAIL CLOSED - an unread BitLocker / TPM / escrow reading resolves to
#      CHECK ERROR or BLOCKED, never READY TO ENABLE.
#   5. NO KEYS LEAK - only KeyProtectorType is ever inspected; no recovery-password
#      value can reach a row, a log line or the CSV.
#
#  THE ONE GAP THAT REMAINS, STATED HONESTLY: a suspend can still fail at EXECUTION
#  time (Suspend-BitLocker throws, or silently no-ops) on a host whose DETECTION was
#  clean. That is not knowable from a read-only probe by construction - no scan can
#  predict it - and it is asserted below as a known, bounded residue rather than
#  papered over.
#
#  Run:  Invoke-Pester -Path .\tests\Secureboot.ScanEnableParity.Tests.ps1
# =============================================================================
$script:Root       = Split-Path $PSScriptRoot -Parent
$script:Mod        = Import-Module (Join-Path $script:Root 'modules\JanetWeb.secureboot.psm1') -Force -PassThru
$script:Src        = Get-Content (Join-Path $script:Root 'modules\JanetWeb.secureboot.psm1') -Raw
$script:View       = Get-Content (Join-Path $script:Root 'web\js\views\secureboot.view.js') -Raw
$script:Payload    = & $script:Mod { $script:SbePayload }
$script:PayloadCore= & $script:Mod { $script:SbePayloadCore }
$script:PostureSrc = & $script:Mod { $script:SbeBitLockerPostureSrc }
$script:CellSrc    = & $script:Mod { $script:SbeScanCellSrc }
$script:ScanWorker = (& $script:Mod { $script:SbeScanWorker }).ToString()

# -----------------------------------------------------------------------------
# Run the REAL SYSTEM payload in a scope where the firmware / disk / BitLocker
# cmdlets it calls are replaced by mocks, and hand back the JSON it wrote.
# (Same harness as Secureboot.BitLockerRefuse.Tests.ps1 - deliberately duplicated
# rather than dot-sourced so this file stands alone.) $PSCommandPath is nulled so
# the payload's self-delete cannot touch a test file.
# -----------------------------------------------------------------------------
function Invoke-SbePayloadForTest {
    param([string]$MockText, [string]$Mfr = 'Dell Inc.', [string]$Firmware = 'UEFI', [string]$Partition = 'GPT')
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('sbep_' + [guid]::NewGuid().ToString('N') + '.json')
    $oldFw = $env:firmware_type
    $env:firmware_type = $Firmware
    $global:__sbeWmiCalls = 0
    $global:__blResumed   = @()
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

# -----------------------------------------------------------------------------
# Run the SHARED posture helper (the exact source the scan probe dot-sources) under
# the SAME mock text, and render the grid cell the scan verdict is derived from.
# This is the scan side of the parity claim: same mocks in, one implementation.
# -----------------------------------------------------------------------------
function Invoke-SbePostureForTest {
    param([string]$MockText)
    $runner = [scriptblock]::Create(@"
param(`$postureSrc, `$cellSrc)
$MockText
. ([scriptblock]::Create(`$postureSrc))
. ([scriptblock]::Create(`$cellSrc))
`$p = Get-SbeBitLockerPosture
[pscustomobject]@{
    Posture = `$p
    Cell    = (ConvertTo-SbeBitLockerCell -Posture `$p)
    Escrow  = [string]`$p.Escrow
}
"@)
    return (& $runner $script:PostureSrc $script:CellSrc)
}

# The admin-side verdict, called exactly the way Invoke-SbeScanAction calls it.
function Get-ScanVerdictFor {
    param([string]$BitLocker, [string]$Escrow, [string]$Tpm = 'Ready',
          [string]$Sb = 'Off', [string]$Fw = 'UEFI', [string]$Disk = 'GPT', [string]$Mfr = 'Dell Inc.')
    & $script:Mod { param($a,$b,$c,$d,$e,$f,$g)
        Get-SbeScanVerdict -SecureBoot $a -Firmware $b -Disk $c -Manufacturer $d -BitLocker $e -Tpm $f -Escrow $g
    } $Sb $Fw $Disk $Mfr $BitLocker $Tpm $Escrow
}

# =============================================================================
#  Mock scopes. The cmdlets-present ones define BOTH Get-BitLockerVolume and
#  Suspend-BitLocker so the helper's `Get-Command` gate finds them; the
#  cmdlets-ABSENT ones shadow Get-Command / Join-Path / Test-Path and route the
#  call operator at a '__sbeMbde' shim (see Secureboot.BitLockerRefuse.Tests.ps1
#  for why the shim carries no param block and sets $LASTEXITCODE itself).
# =============================================================================
$script:MockSuspendFails = @'
function Get-BitLockerVolume { [CmdletBinding()] param($MountPoint)
    [pscustomobject]@{ MountPoint = 'C:'; ProtectionStatus = 'On'; KeyProtector = @([pscustomobject]@{ KeyProtectorType = 'Tpm' }) }
}
function Suspend-BitLocker { [CmdletBinding()] param($MountPoint, $RebootCount) throw 'Access is denied' }
'@

$script:MockSuspendNoOps = @'
function Get-BitLockerVolume { [CmdletBinding()] param($MountPoint)
    [pscustomobject]@{ MountPoint = 'C:'; ProtectionStatus = 'On'; KeyProtector = @([pscustomobject]@{ KeyProtectorType = 'Tpm' }) }
}
function Suspend-BitLocker { [CmdletBinding()] param($MountPoint, $RebootCount) }
'@

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

# TPM-sealed AND carrying a RecoveryPassword protector - there IS a key to type.
$script:MockSealedWithRecovery = @'
function Get-BitLockerVolume { [CmdletBinding()] param($MountPoint)
    if ($MountPoint) { [pscustomobject]@{ MountPoint = 'C:'; ProtectionStatus = $global:__blState; KeyProtector = @() } }
    else { [pscustomobject]@{ MountPoint = 'C:'; ProtectionStatus = 'On'; KeyProtector = @(
        [pscustomobject]@{ KeyProtectorType = 'Tpm' },
        [pscustomobject]@{ KeyProtectorType = 'RecoveryPassword'; RecoveryPassword = '111111-222222-333333-444444-555555-666666-777777-888888' }
    ) } }
}
function Suspend-BitLocker { [CmdletBinding()] param($MountPoint, $RebootCount)
    $global:__blReboot = $RebootCount
    $global:__blState  = 'Off'
}
'@

# Encrypted but NOT TPM-sealed (recovery password only) - no PCR seal to break.
$script:MockNoTpmProtector = @'
function Get-BitLockerVolume { [CmdletBinding()] param($MountPoint)
    [pscustomobject]@{ MountPoint = 'C:'; ProtectionStatus = 'On'; KeyProtector = @([pscustomobject]@{ KeyProtectorType = 'RecoveryPassword' }) }
}
function Suspend-BitLocker { [CmdletBinding()] param($MountPoint, $RebootCount) throw 'must not be called' }
'@

# The cmdlets exist but the volume read itself fails (WMI/RPC down): UNREAD state.
$script:MockBlVolumeThrows = @'
function Get-BitLockerVolume { [CmdletBinding()] param($MountPoint) throw 'The RPC server is unavailable' }
function Suspend-BitLocker { [CmdletBinding()] param($MountPoint, $RebootCount) throw 'must not be called' }
'@

# Protected, but the protector list comes back EMPTY - we cannot tell whether a
# recovery password exists. That is an unread sub-state, not a "no key" fact.
$script:MockProtectorsUnreadable = @'
function Get-BitLockerVolume { [CmdletBinding()] param($MountPoint)
    [pscustomobject]@{ MountPoint = 'C:'; ProtectionStatus = 'On'; KeyProtector = @() }
}
function Suspend-BitLocker { [CmdletBinding()] param($MountPoint, $RebootCount) }
'@

function New-MbdeMock {
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
$script:MockMbdeLocalized   = New-MbdeMock -Body '$global:LASTEXITCODE = 0; "Volume C: [OSDisk]`n    Schutzstatus:    Der Schutz ist aktiviert`n"'
$script:MockMbdeProtectedOn = New-MbdeMock -Body '$global:LASTEXITCODE = 0; "Volume C: [OSDisk]`n    Conversion Status:    Fully Encrypted`n    Protection Status:    Protection On`n"'
$script:MockMbdeAllOff      = New-MbdeMock -Body '$global:LASTEXITCODE = 0; "Volume C: [OSDisk]`n    Conversion Status:    Fully Decrypted`n    Protection Status:    Protection Off`n"'
$script:MockMbdeAbsent      = New-MbdeMock -Body 'throw "must not be called"' -MbdePresent $false

# =============================================================================
Describe 'secureboot 1.7.0 - ONE BitLocker detection implementation, two callers' {

    It 'the SYSTEM payload the launcher ships is COMPOSED from the shared posture source' {
        # Not "the same rules pasted twice" - literally the same characters. If someone
        # ever re-pastes a private copy into the payload body, this goes red.
        ($script:Payload.StartsWith($script:PostureSrc))  | Should Be $true
        ($script:Payload.EndsWith($script:PayloadCore))   | Should Be $true
        ($script:PostureSrc -match 'function Get-SbeBitLockerPosture') | Should Be $true
    }

    It 'the module composes the payload rather than defining a second copy' {
        ($script:Src -match '\$script:SbePayload\s*=\s*\$script:SbeBitLockerPostureSrc\s*\+') | Should Be $true
        # exactly ONE definition of the detection helper in the whole module
        (([regex]::Matches($script:Src, 'function Get-SbeBitLockerPosture')).Count) | Should Be 1
    }

    It 'the scan worker passes the SAME source through to the remote probe' {
        ($script:Src -match '\$postureSrc\s*=\s*\$script:SbeBitLockerPostureSrc') | Should Be $true
        ($script:Src -match '\[void\]\$ps\.AddArgument\(\$postureSrc\); \[void\]\$ps\.AddArgument\(\$cellSrc\)') | Should Be $true
        ($script:ScanWorker -match '\.\s*\(\[scriptblock\]::Create\(\$PostureSrc\)\)') | Should Be $true
        ($script:ScanWorker -match 'Get-SbeBitLockerPosture')                          | Should Be $true
    }

    Context 'the enable path keeps ONLY the write half (AST over the real payload)' {
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Payload, [ref]$null, [ref]$null)
        $fn  = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                              $n.Name -eq 'Suspend-TpmBitLockerForFirmware' }, $true) | Select-Object -First 1
        $body = if ($fn) { $fn.Extent.Text } else { '' }

        It 'Suspend-TpmBitLockerForFirmware exists and DELEGATES detection to the shared helper' {
            ($null -eq $fn)                        | Should Be $false
            ($body -match 'Get-SbeBitLockerPosture') | Should Be $true
        }
        It 'it holds NO detection logic of its own - the scan therefore cannot diverge from it' {
            # Each of these is a detection marker. Every one now lives only in the shared
            # helper; a copy reappearing here is precisely the drift this task removed.
            ($body -match 'manage-bde')            | Should Be $false
            ($body -match 'Protection\s+Status')   | Should Be $false
            ($body -match 'tpmTypes')              | Should Be $false
            ($body -match 'KeyProtectorType')      | Should Be $false
            ($body -match 'Get-Command')           | Should Be $false
        }
        It 'the detection markers it gave up are all present in the shared helper' {
            ($script:PostureSrc -match 'manage-bde')          | Should Be $true
            ($script:PostureSrc -match 'Protection\s+Status') | Should Be $true
            ($script:PostureSrc -match "\`$tpmTypes\s*=\s*@\('Tpm','TpmPin','TpmStartupKey','TpmPinStartupKey'\)") | Should Be $true
            ($script:PostureSrc -match 'KeyProtectorType')    | Should Be $true
        }
        It 'the v1.6.9 fail-closed manage-bde parser survived the refactor verbatim' {
            ($script:PostureSrc -match "\[regex\]::Matches\(\`$st, '\(\?im\)\^\\s\*Protection\\s\+Status:\\s\*\(\.\+\?\)\\s\*\$'\)") | Should Be $true
            ($script:PostureSrc -match 'the output may be localized')                      | Should Be $true
            ($script:PostureSrc -match 'manage-bde -status failed or returned no output')   | Should Be $true
            ($script:PostureSrc -match 'a protection state this payload does not recognise')| Should Be $true
        }
    }
}

# =============================================================================
Describe 'secureboot 1.7.0 - the READ-ONLY scan path can never write BitLocker' {

    # Over INVOKED COMMANDS, via the parser - not over source text. A regex for
    # 'Suspend-BitLocker' would be satisfied by the word appearing in a comment, or
    # tripped by the helper's own `Get-Command Suspend-BitLocker` presence gate (which
    # invokes Get-Command, not Suspend-BitLocker). Ask the AST what is actually called.
    function Get-InvokedCommandNames {
        param([string]$Source)
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($Source, [ref]$null, [ref]$null)
        @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
            ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
    }
    $script:WriteVerbs = @('Suspend-BitLocker','Resume-BitLocker','Enable-BitLocker','Disable-BitLocker',
                           'Unlock-BitLocker','Lock-BitLocker','Add-BitLockerKeyProtector',
                           'Remove-BitLockerKeyProtector','Backup-BitLockerKeyProtector','Clear-Tpm','Initialize-Tpm')

    It 'the shared posture helper INVOKES no BitLocker/TPM write cmdlet' {
        $called = Get-InvokedCommandNames $script:PostureSrc
        $bad    = @($called | Where-Object { $script:WriteVerbs -contains $_ })
        ($bad -join ',') | Should Be ''
        # ...and it does read the two it gates on, so the assertion above is not vacuous.
        ($called -contains 'Get-BitLockerVolume') | Should Be $true
        ($called -contains 'Get-Command')         | Should Be $true
    }
    It 'the only manage-bde invocation in the helper is the read-only -status' {
        (([regex]::Matches($script:PostureSrc, '&\s+\$mbde\s+-status')).Count) | Should Be 1
        ($script:PostureSrc -match '-forcerecovery|-protectors\s+-(add|delete)|manage-bde\s+-(on|off)\b') | Should Be $false
    }
    It 'the scan worker + cell renderer INVOKE no BitLocker/TPM write cmdlet either' {
        $called = Get-InvokedCommandNames ($script:ScanWorker + "`r`n" + $script:CellSrc)
        $bad    = @($called | Where-Object { $script:WriteVerbs -contains $_ })
        ($bad -join ',') | Should Be ''
        ($called -contains 'Invoke-Command') | Should Be $true   # the probe really is wired up
    }
    It 'the scan action stays destructive=$false with no arm gate bolted on' {
        $man  = & $script:Mod { Get-JanetToolManifest }
        $scan = @($man.actions | Where-Object { $_.id -eq 'scan-secure-boot' })[0]
        [bool]$scan.destructive | Should Be $false
        ($null -eq $scan.confirm) | Should Be $true
        @($scan.inputs | Where-Object { $_.name -eq 'confirm' }).Count | Should Be 0
    }
    It 'the enable path keeps its typed confirm word, self-guard and wrong-box guard' {
        ($script:Src -match "\[string\]\`$Params\['confirm'\] -cne 'ENABLE'") | Should Be $true
        ($script:Src -match 'if \(Test-JanetSbeHostIsSelf \$t\)')             | Should Be $true
        ($script:Src -match "throw \""wrong box: dialed")                     | Should Be $true
        # the self-guard's unary comma (a bare `return $set` unrolls the HashSet and
        # silently kills the case-insensitive compare) is untouched.
        ($script:Src -match 'return ,\$set')                                  | Should Be $true
    }
}

# =============================================================================
#  THE DELIVERABLE'S PROOF. Each case runs the REAL payload and the REAL posture
#  helper under the SAME mock scope, then scores the scan verdict from that
#  posture exactly as Invoke-SbeScanAction does.
# =============================================================================
Describe 'secureboot 1.7.0 - a state the ENABLE path refuses is never scored READY TO ENABLE' {

    Context 'states the shared DETECTION refuses (both callers agree by construction)' {

        It 'manage-bde THROWING: payload Refuses, scan says CHECK ERROR' {
            $obj = Invoke-SbePayloadForTest -MockText $script:MockMbdeThrows -Mfr 'Dell Inc.'
            $pos = Invoke-SbePostureForTest -MockText $script:MockMbdeThrows
            [string]$obj.SetResult | Should Be 'Refused'
            $global:__sbeWmiCalls  | Should Be 0
            [bool]$pos.Posture.Readable | Should Be $false
            [string]$pos.Cell           | Should Be 'Unknown'
            (Get-ScanVerdictFor -BitLocker $pos.Cell -Escrow $pos.Escrow) | Should Be 'CHECK ERROR'
        }
        It 'EMPTY manage-bde output: payload Refuses, scan says CHECK ERROR' {
            $obj = Invoke-SbePayloadForTest -MockText $script:MockMbdeEmpty -Mfr 'Dell Inc.'
            $pos = Invoke-SbePostureForTest -MockText $script:MockMbdeEmpty
            [string]$obj.SetResult | Should Be 'Refused'
            [string]$pos.Cell      | Should Be 'Unknown'
            (Get-ScanVerdictFor -BitLocker $pos.Cell -Escrow $pos.Escrow) | Should Be 'CHECK ERROR'
        }
        It 'NON-ZERO manage-bde exit: payload Refuses, scan says CHECK ERROR' {
            $obj = Invoke-SbePayloadForTest -MockText $script:MockMbdeNonZeroExit -Mfr 'Dell Inc.'
            $pos = Invoke-SbePostureForTest -MockText $script:MockMbdeNonZeroExit
            [string]$obj.SetResult | Should Be 'Refused'
            [string]$pos.Cell      | Should Be 'Unknown'
            (Get-ScanVerdictFor -BitLocker $pos.Cell -Escrow $pos.Escrow) | Should Be 'CHECK ERROR'
        }
        It 'LOCALIZED manage-bde output: payload Refuses, scan says CHECK ERROR' {
            $obj = Invoke-SbePayloadForTest -MockText $script:MockMbdeLocalized -Mfr 'Dell Inc.'
            $pos = Invoke-SbePostureForTest -MockText $script:MockMbdeLocalized
            [string]$obj.SetResult | Should Be 'Refused'
            $obj.Error             | Should Match 'localized'
            [string]$pos.Cell      | Should Be 'Unknown'
            (Get-ScanVerdictFor -BitLocker $pos.Cell -Escrow $pos.Escrow) | Should Be 'CHECK ERROR'
        }
        It 'protection ON with the cmdlets gone: payload Refuses, scan says BLOCKED - BITLOCKER UNSUSPENDABLE' {
            # THE HEADLINE CASE. This host used to read READY TO ENABLE and then come back
            # 'Refused' after the operator armed a fleet firmware write.
            $obj = Invoke-SbePayloadForTest -MockText $script:MockMbdeProtectedOn -Mfr 'Dell Inc.'
            $pos = Invoke-SbePostureForTest -MockText $script:MockMbdeProtectedOn
            [string]$obj.SetResult | Should Be 'Refused'
            $obj.Error             | Should Match 'protection is ON'
            $global:__sbeWmiCalls  | Should Be 0
            [bool]$pos.Posture.Blocked | Should Be $true
            [string]$pos.Cell          | Should Be 'On (UNSUSPENDABLE)'
            (Get-ScanVerdictFor -BitLocker $pos.Cell -Escrow $pos.Escrow) | Should Be 'BLOCKED - BITLOCKER UNSUSPENDABLE'
        }
        It 'the volume read itself throwing: payload Refuses, scan says CHECK ERROR' {
            $obj = Invoke-SbePayloadForTest -MockText $script:MockBlVolumeThrows -Mfr 'Dell Inc.'
            $pos = Invoke-SbePostureForTest -MockText $script:MockBlVolumeThrows
            [string]$obj.SetResult | Should Be 'Refused'
            $obj.Error             | Should Match 'Could not read BitLocker volume state'
            $global:__sbeWmiCalls  | Should Be 0
            [string]$pos.Cell      | Should Be 'Unknown'
            (Get-ScanVerdictFor -BitLocker $pos.Cell -Escrow $pos.Escrow) | Should Be 'CHECK ERROR'
        }
    }

    Context 'states the DETECTION permits (both callers agree the other way too)' {

        It 'every volume positively Protection Off: payload proceeds, scan says READY TO ENABLE' {
            $obj = Invoke-SbePayloadForTest -MockText $script:MockMbdeAllOff -Mfr 'Contoso'
            $pos = Invoke-SbePostureForTest -MockText $script:MockMbdeAllOff
            [bool]$obj.Refused | Should Be $false
            [string]$pos.Cell  | Should Be 'Off'
            [string]$pos.Escrow| Should Be 'n/a'
            (Get-ScanVerdictFor -BitLocker $pos.Cell -Escrow $pos.Escrow) | Should Be 'READY TO ENABLE'
        }
        It 'BitLocker genuinely not installed: payload proceeds, scan says READY TO ENABLE' {
            $obj = Invoke-SbePayloadForTest -MockText $script:MockMbdeAbsent -Mfr 'Contoso'
            $pos = Invoke-SbePostureForTest -MockText $script:MockMbdeAbsent
            [bool]$obj.Refused | Should Be $false
            $obj.BitLocker     | Should Match 'both absent'
            [string]$pos.Cell  | Should Be 'Off'
            (Get-ScanVerdictFor -BitLocker $pos.Cell -Escrow $pos.Escrow) | Should Be 'READY TO ENABLE'
        }
        It 'encrypted but NOT TPM-sealed with a recovery password: nothing to suspend, READY TO ENABLE' {
            $obj = Invoke-SbePayloadForTest -MockText $script:MockNoTpmProtector -Mfr 'Contoso'
            $pos = Invoke-SbePostureForTest -MockText $script:MockNoTpmProtector
            [bool]$obj.Refused | Should Be $false
            $obj.BitLocker     | Should Match 'No TPM-sealed BitLocker volume'
            [string]$pos.Cell  | Should Be 'On (no TPM seal)'
            [string]$pos.Escrow| Should Be 'RecoveryPassword'
            (Get-ScanVerdictFor -BitLocker $pos.Cell -Escrow $pos.Escrow) | Should Be 'READY TO ENABLE'
        }
        It 'TPM-sealed WITH an escrowed recovery password: suspendable + a key exists, READY TO ENABLE' {
            $global:__blState = 'On'
            $obj = Invoke-SbePayloadForTest -MockText $script:MockSealedWithRecovery -Mfr 'Contoso'
            $pos = Invoke-SbePostureForTest -MockText $script:MockSealedWithRecovery
            [bool]$obj.Refused | Should Be $false
            $obj.BitLocker     | Should Match 'Suspended for 1 reboot'
            [string]$pos.Cell  | Should Be 'On (TPM-sealed, suspendable)'
            [string]$pos.Escrow| Should Be 'RecoveryPassword'
            (Get-ScanVerdictFor -BitLocker $pos.Cell -Escrow $pos.Escrow) | Should Be 'READY TO ENABLE'
        }
    }

    Context 'the RISK tier - suspendable, but there is no key to type if that boot asks' {

        It 'TPM-sealed with NO RecoveryPassword protector scores RISK - NO ESCROWED KEY, not READY' {
            # The audit''s "installed base": MECM/imaging-encrypted, TPM-only, never escrowed.
            $global:__blState = 'On'
            $pos = Invoke-SbePostureForTest -MockText $script:MockSuspendWorks
            [string]$pos.Cell   | Should Be 'On (TPM-sealed, suspendable)'
            [string]$pos.Escrow | Should Be 'NONE'
            (Get-ScanVerdictFor -BitLocker $pos.Cell -Escrow $pos.Escrow) | Should Be 'RISK - NO ESCROWED KEY'
        }
        It 'a protected volume whose protector list is UNREADABLE is CHECK ERROR, not NONE and not READY' {
            $pos = Invoke-SbePostureForTest -MockText $script:MockProtectorsUnreadable
            [string]$pos.Escrow | Should Be 'Unknown'
            (Get-ScanVerdictFor -BitLocker $pos.Cell -Escrow $pos.Escrow) | Should Be 'CHECK ERROR'
        }
        It 'RISK hosts are excluded from the READY list the operator hands to Enable' {
            # readyHosts is filled only from the exact READY TO ENABLE verdict.
            ($script:Src -match "if \(\`$verdict -eq 'READY TO ENABLE'\) \{ \[void\]\`$readyHosts\.Add") | Should Be $true
        }
    }

    Context 'the residual gap, stated honestly: EXECUTION failures are not readable' {
        # A suspend can still fail when it is actually attempted, on a host whose
        # DETECTION was clean. No read-only probe can predict that - so the contract is
        # "detection can never diverge", not "the scan predicts every refusal". Even so,
        # neither execution-failure case lands on READY TO ENABLE.
        It 'Suspend-BitLocker throwing still Refuses at write time - and the scan is NOT green' {
            $obj = Invoke-SbePayloadForTest -MockText $script:MockSuspendFails -Mfr 'Dell Inc.'
            $pos = Invoke-SbePostureForTest -MockText $script:MockSuspendFails
            [string]$obj.SetResult | Should Be 'Refused'
            $global:__sbeWmiCalls  | Should Be 0
            (Get-ScanVerdictFor -BitLocker $pos.Cell -Escrow $pos.Escrow) | Should Not Be 'READY TO ENABLE'
        }
        It 'a silently no-op suspend still Refuses - and the scan is NOT green' {
            $obj = Invoke-SbePayloadForTest -MockText $script:MockSuspendNoOps -Mfr 'Dell Inc.'
            $pos = Invoke-SbePostureForTest -MockText $script:MockSuspendNoOps
            [string]$obj.SetResult | Should Be 'Refused'
            (Get-ScanVerdictFor -BitLocker $pos.Cell -Escrow $pos.Escrow) | Should Not Be 'READY TO ENABLE'
        }
    }

    It 'THE INVARIANT: across every BitLocker state in this suite, no host the payload Refuses is READY' {
        $cases = @(
            @{ N='mbde throws';        M=$script:MockMbdeThrows      },
            @{ N='mbde empty';         M=$script:MockMbdeEmpty       },
            @{ N='mbde non-zero exit'; M=$script:MockMbdeNonZeroExit },
            @{ N='mbde localized';     M=$script:MockMbdeLocalized   },
            @{ N='mbde protection on'; M=$script:MockMbdeProtectedOn },
            @{ N='volume read throws'; M=$script:MockBlVolumeThrows  },
            @{ N='suspend throws';     M=$script:MockSuspendFails    },
            @{ N='suspend no-ops';     M=$script:MockSuspendNoOps    }
        )
        $violations = New-Object System.Collections.ArrayList
        foreach ($c in $cases) {
            $global:__blState = 'On'
            $obj = Invoke-SbePayloadForTest -MockText $c.M -Mfr 'Dell Inc.'
            $pos = Invoke-SbePostureForTest -MockText $c.M
            $v   = Get-ScanVerdictFor -BitLocker $pos.Cell -Escrow $pos.Escrow
            if (([string]$obj.SetResult -eq 'Refused') -and ($v -eq 'READY TO ENABLE')) {
                [void]$violations.Add("$($c.N) -> payload Refused but scan said READY TO ENABLE")
            }
        }
        ($violations -join '; ') | Should Be ''
    }
}

# =============================================================================
Describe 'secureboot 1.7.0 - the verdict function FAILS CLOSED on every unread axis' {

    It 'an OMITTED BitLocker/TPM/escrow reading is CHECK ERROR, never a permissive default' {
        # A caller that forgets to supply the posture must not be able to get a green
        # verdict out of this function. Empty normalises to 'Unknown'.
        (& $script:Mod { Get-SbeScanVerdict -SecureBoot 'Off' -Firmware 'UEFI' -Disk 'GPT' -Manufacturer 'Dell Inc.' }) | Should Be 'CHECK ERROR'
    }
    It 'an unreadable BitLocker state is CHECK ERROR' {
        (Get-ScanVerdictFor -BitLocker 'Unknown' -Escrow 'n/a' -Tpm 'Ready') | Should Be 'CHECK ERROR'
    }
    It 'an unreadable TPM state is CHECK ERROR even when BitLocker reads clean' {
        (Get-ScanVerdictFor -BitLocker 'Off' -Escrow 'n/a' -Tpm 'Unknown') | Should Be 'CHECK ERROR'
    }
    It 'an unreadable escrow state is CHECK ERROR' {
        (Get-ScanVerdictFor -BitLocker 'On (TPM-sealed, suspendable)' -Escrow 'Unknown' -Tpm 'Ready') | Should Be 'CHECK ERROR'
    }
    It 'UNSUSPENDABLE outranks every other downgrade - it is the one the enable path refuses' {
        (Get-ScanVerdictFor -BitLocker 'On (UNSUSPENDABLE)' -Escrow 'Unknown' -Tpm 'Unknown') | Should Be 'BLOCKED - BITLOCKER UNSUSPENDABLE'
    }
    It 'a positively-read TPM state that is not Ready does not by itself block a host with no BitLocker' {
        # 'Absent' / 'Present - not ready' are FACTS, not unread states. A box with no
        # TPM and no BitLocker protection has nothing a firmware write can strand.
        (Get-ScanVerdictFor -BitLocker 'Off' -Escrow 'n/a' -Tpm 'Absent')              | Should Be 'READY TO ENABLE'
        (Get-ScanVerdictFor -BitLocker 'Off' -Escrow 'n/a' -Tpm 'Present - not ready') | Should Be 'READY TO ENABLE'
    }
    It 'the pre-existing Secure Boot / firmware / disk axes are unchanged' {
        (Get-ScanVerdictFor -BitLocker 'Off' -Escrow 'n/a' -Sb 'On')                    | Should Be 'ENABLED'
        (Get-ScanVerdictFor -BitLocker 'Off' -Escrow 'n/a' -Fw 'Legacy')                | Should Be 'BLOCKED - LEGACY/MBR'
        (Get-ScanVerdictFor -BitLocker 'Off' -Escrow 'n/a' -Disk 'MBR')                 | Should Be 'BLOCKED - LEGACY/MBR'
        (Get-ScanVerdictFor -BitLocker 'Off' -Escrow 'n/a' -Sb 'Unknown')               | Should Be 'CHECK ERROR'
        (Get-ScanVerdictFor -BitLocker 'Off' -Escrow 'n/a' -Mfr 'VMware, Inc.')         | Should Be 'OFF - UNSUPPORTED OEM'
    }
    It 'an ALREADY-ENABLED host is never downgraded by BitLocker - no write happens on it' {
        (Get-ScanVerdictFor -BitLocker 'On (UNSUSPENDABLE)' -Escrow 'NONE' -Tpm 'Unknown' -Sb 'On') | Should Be 'ENABLED'
    }
}

# =============================================================================
Describe 'secureboot 1.7.0 - no recovery key can reach a row, a log or the CSV' {

    It 'the shared helper reads protector TYPES only - never a recovery password value' {
        # Guard for the audit''s own warning on the escrow work: a fix for a key-visibility
        # gap must not itself leak keys.
        ($script:PostureSrc -match '\$_\.RecoveryPassword')       | Should Be $false
        ($script:PostureSrc -match '\.RecoveryPassword\b')        | Should Be $false
        ($script:PostureSrc -match 'KeyProtectorType')            | Should Be $true
    }
    It 'no emitted posture field carries a 48-digit BitLocker recovery password' {
        # Driven through a mock whose RecoveryPassword protector really does carry a key.
        $global:__blState = 'On'
        $pos  = Invoke-SbePostureForTest -MockText $script:MockSealedWithRecovery
        $blob = (($pos.Posture | ConvertTo-Json -Depth 6) + '|' + $pos.Cell + '|' + $pos.Escrow)
        ($blob -match '\d{6}(-\d{6}){7}') | Should Be $false
    }
    It 'the module never touches a RecoveryPassword value anywhere' {
        ($script:Src -match '\.RecoveryPassword\b')  | Should Be $false
        ($script:Src -match 'ConvertFrom-SecureString|RecoveryKey\b') | Should Be $false
    }
}

# =============================================================================
Describe 'secureboot 1.7.0 - manifest + scan wiring + view carry the new posture' {

    $man  = & $script:Mod { Get-JanetToolManifest }
    $scan = @($man.actions | Where-Object { $_.id -eq 'scan-secure-boot' })[0]

    It 'the scan declares BitLocker, TPM and Escrow columns' {
        (@($scan.columns) -contains 'BitLocker') | Should Be $true
        (@($scan.columns) -contains 'TPM')       | Should Be $true
        (@($scan.columns) -contains 'Escrow')    | Should Be $true
    }
    It 'this is the EXISTING scan action extended, not a new action' {
        @($man.actions).Count | Should Be 2
        (($man.actions | ForEach-Object { $_.id }) -join ',') | Should Be 'scan-secure-boot,enable-secure-boot'
    }
    It 'the emitted scan row carries the three new cells, and the seed row does too' {
        ($script:Src -match 'BitLocker=\[string\]\$res\.BitLocker; TPM=\[string\]\$res\.Tpm; Escrow=\[string\]\$res\.Escrow') | Should Be $true
        ($script:Src -match "Verdict='Queued'; SecureBoot=''; Firmware=''; Disk=''; BitLocker=''; TPM=''; Escrow=''") | Should Be $true
    }
    It 'every fallback scan row shape (worker error / no result / timeout / cancel) carries them too' {
        (([regex]::Matches($script:Src, "Disk='\?'; BitLocker='\?'; Tpm='\?'; Escrow='\?'")).Count) | Should Be 5
    }
    It 'the scan verdict call feeds the posture through' {
        ($script:Src -match '-BitLocker \(\[string\]\$res\.BitLocker\) -Tpm \(\[string\]\$res\.Tpm\) -Escrow \(\[string\]\$res\.Escrow\)') | Should Be $true
    }
    It 'the new verdicts are tallied (they were invisible in the counts otherwise)' {
        ($script:Src -match "'RISK - NO ESCROWED KEY','OFF - UNSUPPORTED OEM','BLOCKED - LEGACY/MBR','BLOCKED - BITLOCKER UNSUSPENDABLE'") | Should Be $true
        ($script:Src -match 'bitlockerBlocked\s*=\s*\$blBlocked') | Should Be $true
        ($script:Src -match 'noEscrowedKey\s*=\s*\$noEscrow')     | Should Be $true
    }
    It 'the view renders the three columns and colours the two new verdicts' {
        ($script:View -match "key: 'BitLocker', label: 'BITLOCKER', width: 150, render") | Should Be $true
        ($script:View -match "key: 'TPM', label: 'TPM'")                                  | Should Be $true
        ($script:View -match "key: 'Escrow', label: 'ESCROW'")                            | Should Be $true
        ($script:View -match "case 'BLOCKED - BITLOCKER UNSUSPENDABLE': return 'st-bad';")| Should Be $true
        ($script:View -match "case 'RISK - NO ESCROWED KEY': return 'st-warn';")          | Should Be $true
        # neither new verdict may paint a row green
        ($script:View -match "s === 'ENABLED' \|\| s === 'READY TO ENABLE'\) return 'row-ok'") | Should Be $true
    }
    It 'the scan CSV export carries the three new columns' {
        ($script:View -match "\['Disk', 'Disk'\], \['BitLocker', 'BitLocker'\], \['TPM', 'TPM'\], \['Escrow', 'Escrow'\]") | Should Be $true
    }
    It 'the completion dialog reports both new buckets' {
        ($script:View -match 'RISK - no escrowed recovery key')          | Should Be $true
        ($script:View -match 'Blocked \(BitLocker unsuspendable\)')      | Should Be $true
    }
}
