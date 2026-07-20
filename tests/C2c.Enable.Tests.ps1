# =============================================================================
#  C2c.Enable.Tests.ps1 - Pester 3.4 tests for the C2C v1.4.0 fix-encryption
#  opt-in BitLocker ENABLE path (Encryption pillar). Proves the enable sequence
#  MIRRORS the enterprise USAF enable script - (1) assert FVE policy, (2) reuse-
#  or-add a RecoveryPassword protector, (3) escrow Entra-first with an on-prem AD
#  fallback, (4) Enable-BitLocker - while KEEPING our deliberate fail-closed
#  semantics (if BOTH escrow paths fail, Enable is unreachable and the pillar
#  FAILs; a protector we added is removed, a pre-existing one is not).
#
#  Driven with the suite's shim idiom: New-PSSession / Remove-PSSession /
#  Invoke-Command, every BitLocker/TPM/CIM cmdlet, the Entra + AD escrow cmdlets,
#  and the FVE-policy registry cmdlets (Get-Item / New-Item / New-ItemProperty)
#  are shadowed IN MODULE SCOPE, so the enable logic runs LOCALLY against fakes
#  and NO WinRM call and NO real registry write ever leaves this box.
#
#  The shimmed Invoke-Command EXECUTES the remote fix scriptblock locally
#  (& $ScriptBlock @ArgumentList) against the shimmed cmdlets, which is how the
#  Policy -> Add -> escrow -> Enable order and the recovery-password redaction
#  are observed.
#
#  Run:  Invoke-Pester -Path .\tests\C2c.Enable.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$cm = Import-Module (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1') -Force -PassThru

# Drive the per-host worker with mocked cmdlets. $Scenario tunes the fakes:
#   happy           - policy ok, no pre-existing protector, Entra escrow succeeds.
#   entrafail       - Entra throws, on-prem AD escrow succeeds.
#   bothfail        - both escrow paths throw; WE added the protector.
#   preexisthappy   - a RecoveryPassword protector already exists; Entra succeeds.
#   preexistbothfail- pre-existing protector; both escrow paths throw.
#   policyfail      - the FVE policy registry write throws.
#   tpmnotready | notdomain - precondition gates (unchanged).
function Invoke-C2cEnable {
    param([bool]$DoEnable, [string]$Scenario = 'happy')
    & $cm {
        param($DoEnable, $Scenario)
        $sentinel = 'SENTINEL-RECOVERY-123456-DO-NOT-LEAK'
        $script:__order       = New-Object System.Collections.ArrayList
        $script:__blCalls     = 0
        $script:__scenario    = $Scenario
        $script:__sentinel    = $sentinel
        $script:__encMethod   = ''
        $script:__usedSpace   = $false
        $script:__escrowId    = ''
        $script:__preexist    = ($Scenario -eq 'preexisthappy' -or $Scenario -eq 'preexistbothfail')
        $script:__entraThrow  = ($Scenario -eq 'entrafail' -or $Scenario -eq 'bothfail' -or $Scenario -eq 'preexistbothfail' -or $Scenario -eq 'bothfailblankid')
        $script:__adThrow     = ($Scenario -eq 'bothfail' -or $Scenario -eq 'preexistbothfail' -or $Scenario -eq 'bothfailblankid')
        # bothfailblankid: Add succeeds but returns NO resolvable protector id, so
        # $newKpId stays blank; escrow then fails and the v1.15.2 orphan-cleanup path
        # must re-enumerate and remove the just-added protector (never a pre-existing).
        $script:__blankId     = ($Scenario -eq 'bothfailblankid')
        $script:__removeIds   = New-Object System.Collections.ArrayList

        function script:New-PSSession { param($ComputerName, $SessionOption, $Authentication, $ErrorAction, $Credential) [pscustomobject]@{ Id = 1; Name = 'shim' } }
        function script:Remove-PSSession { param($Session, $ErrorAction) }
        function script:Invoke-Command {
            param($Session, $ComputerName, $ScriptBlock, $ArgumentList, $ErrorAction, $Credential, $Authentication, $SessionOption)
            if ($ScriptBlock -and ($ScriptBlock.ToString().Trim() -eq '$env:COMPUTERNAME')) { return $env:COMPUTERNAME }
            return (& $ScriptBlock @ArgumentList)
        }
        function script:Get-BitLockerVolume {
            param($MountPoint, $ErrorAction)
            $script:__blCalls++
            if ($script:__blCalls -eq 1) {
                $kps = @()
                if ($script:__preexist) { $kps = @([pscustomobject]@{ KeyProtectorType = 'RecoveryPassword'; KeyProtectorId = '{PRE-KP}'; RecoveryPassword = $script:__sentinel }) }
                return [pscustomobject]@{ ProtectionStatus = 'Off'; VolumeStatus = 'FullyDecrypted'; VolumeType = 'OperatingSystem'; EncryptionPercentage = 0; KeyProtector = $kps }
            }
            # blank-id orphan cleanup re-read (Enable never runs in bothfailblankid, so
            # this call 2 IS the cleanup enumeration): the just-added RP protector now
            # surfaces with a resolvable id NOT present before the Add ($beforeIds was empty).
            if ($script:__blankId) {
                return [pscustomobject]@{ ProtectionStatus = 'Off'; VolumeStatus = 'FullyDecrypted'; VolumeType = 'OperatingSystem'; EncryptionPercentage = 0; KeyProtector = @([pscustomobject]@{ KeyProtectorType = 'RecoveryPassword'; KeyProtectorId = '{LATE-KP}'; RecoveryPassword = $script:__sentinel }) }
            }
            # post-Enable verify re-read
            return [pscustomobject]@{ ProtectionStatus = 'Off'; VolumeStatus = 'EncryptionInProgress'; VolumeType = 'OperatingSystem'; EncryptionPercentage = 2; KeyProtector = @() }
        }
        function script:Get-Tpm {
            param($ErrorAction)
            if ($script:__scenario -eq 'tpmnotready') { return [pscustomobject]@{ TpmPresent = $true; TpmReady = $false; TpmEnabled = $true } }
            return [pscustomobject]@{ TpmPresent = $true; TpmReady = $true; TpmEnabled = $true }
        }
        function script:Get-CimInstance {
            # NB simple function (no [Parameter] attribute) so it stays non-advanced and
            # does NOT gain an automatic -ErrorAction that would collide with the explicit
            # $ErrorAction param. First positional arg = class name.
            param($ClassName, $Namespace, $Query, $Filter, $ErrorAction)
            $joined = ($script:__scenario -ne 'notdomain')
            return [pscustomobject]@{ PartOfDomain = $joined }
        }
        # --- FVE policy registry shims (no real HKLM write) ---------------------
        function script:Get-Item {
            param($LiteralPath, $Path, $ErrorAction)
            # Return a fake registry key whose GetValue() reports "value absent" so the
            # policy assert treats every value as set/corrected (no real registry read).
            $o = New-Object psobject
            Add-Member -InputObject $o -MemberType ScriptMethod -Name GetValue -Value { param($n, $d) $null }
            return $o
        }
        function script:New-Item { param($Path, [switch]$Force, $ErrorAction) }
        function script:New-ItemProperty {
            param($Path, $Name, $PropertyType, $Value, [switch]$Force, $ErrorAction)
            if ($script:__scenario -eq 'policyfail') { throw 'registry write denied (test)' }
            if (-not ($script:__order -contains 'Policy')) { [void]$script:__order.Add('Policy') }
        }
        # --- protector + escrow shims -------------------------------------------
        function script:Add-BitLockerKeyProtector {
            param($MountPoint, [switch]$RecoveryPasswordProtector, $ErrorAction)
            [void]$script:__order.Add('Add')
            # bothfailblankid: the Add return carries NO resolvable RP protector, so the
            # engine's add-time id resolution leaves $newKpId blank (the near-impossible case).
            if ($script:__blankId) { return [pscustomobject]@{ KeyProtector = @() } }
            return [pscustomobject]@{ KeyProtector = @([pscustomobject]@{ KeyProtectorType = 'RecoveryPassword'; KeyProtectorId = '{NEW-KP}'; RecoveryPassword = $script:__sentinel }) }
        }
        function script:BackupToAAD-BitLockerKeyProtector {
            param($MountPoint, $KeyProtectorId, $ErrorAction)
            [void]$script:__order.Add('Entra')
            $script:__escrowId = [string]$KeyProtectorId
            if ($script:__entraThrow) { throw 'Entra (AAD) escrow failed (test)' }
        }
        function script:Backup-BitLockerKeyProtector {
            param($MountPoint, $KeyProtectorId, $ErrorAction)
            [void]$script:__order.Add('AD')
            $script:__escrowId = [string]$KeyProtectorId
            if ($script:__adThrow) { throw 'AD backup RPC failed (test)' }
        }
        function script:Remove-BitLockerKeyProtector {
            param($MountPoint, $KeyProtectorId, $ErrorAction)
            [void]$script:__order.Add('Remove')
            [void]$script:__removeIds.Add([string]$KeyProtectorId)
        }
        function script:Enable-BitLocker {
            param($MountPoint, [switch]$TpmProtector, $EncryptionMethod, [switch]$SkipHardwareTest, [switch]$UsedSpaceOnly, $ErrorAction)
            [void]$script:__order.Add('Enable')
            $script:__encMethod = [string]$EncryptionMethod
            $script:__usedSpace = [bool]$UsedSpaceOnly
        }

        try {
            # target = self so the wrong-box guard passes (answering box == dialed short name).
            # v1.5.0 worker signature: Computer, Cred, Auth, AttemptOffline, Pillars[], DoEnable, TaniumService, TaniumInstalledSrc.
            $res = & $script:C2cFixBlock $env:COMPUTERNAME $null 'Default' $true @('Encryption') $DoEnable 'Tanium Client' $script:C2cTaniumInstalledSrc
            $pillars = @($res.Pillars)
            $enc = @($pillars | Where-Object { $_.Name -eq 'Encryption' })
            $blob = ''
            foreach ($p in $pillars) { $blob += ('|' + [string]$p.Name + '|' + [string]$p.Result + '|' + [string]$p.Detail) }
            $blob += ('|' + [string]$res.Detail + '|' + [string]$res.Report)
            [pscustomobject]@{
                Status         = [string]$res.Status
                EncResult      = $(if ($enc.Count) { [string]$enc[0].Result } else { '' })
                EncDetail      = $(if ($enc.Count) { [string]$enc[0].Detail } else { '' })
                Report         = [string]$res.Report
                Order          = @($script:__order.ToArray())
                PolicyAsserted = (@($script:__order) -contains 'Policy')
                AddCalled      = (@($script:__order) -contains 'Add')
                EntraCalled    = (@($script:__order) -contains 'Entra')
                AdCalled       = (@($script:__order) -contains 'AD')
                RemoveCalled   = (@($script:__order) -contains 'Remove')
                RemoveIds      = @($script:__removeIds.ToArray())
                EnableCalled   = (@($script:__order) -contains 'Enable')
                EscrowId       = [string]$script:__escrowId
                EncMethod      = [string]$script:__encMethod
                UsedSpaceOnly  = [bool]$script:__usedSpace
                Leaked         = [bool]($blob -match [regex]::Escape($script:__sentinel))
            }
        } finally {
            Remove-Item function:script:New-PSSession, function:script:Remove-PSSession, function:script:Invoke-Command, `
                function:script:Get-BitLockerVolume, function:script:Get-Tpm, function:script:Get-CimInstance, `
                function:script:Get-Item, function:script:New-Item, function:script:New-ItemProperty, `
                function:script:Add-BitLockerKeyProtector, function:script:BackupToAAD-BitLockerKeyProtector, `
                function:script:Backup-BitLockerKeyProtector, `
                function:script:Remove-BitLockerKeyProtector, function:script:Enable-BitLocker -ErrorAction SilentlyContinue
        }
    } $DoEnable $Scenario
}

# -----------------------------------------------------------------------------
Describe 'C2C Mass Fix v1.3.0 - opt-in BitLocker ENABLE (USAF-aligned, escrow-first, fail-closed)' {

    It '(a) FVE policy assert FAILS => Add / escrow / Enable all uncalled, result FAIL' {
        $r = Invoke-C2cEnable -DoEnable $true -Scenario 'policyfail'
        $r.EncResult    | Should Be 'FAIL'
        $r.EncDetail    | Should Match 'FVE policy assert failed'
        $r.AddCalled    | Should Be $false
        $r.EntraCalled  | Should Be $false
        $r.AdCalled     | Should Be $false
        $r.EnableCalled | Should Be $false
    }

    It '(b) a pre-existing RecoveryPassword protector is REUSED (no Add), its id is escrowed, and on double-escrow-failure it is NOT removed' {
        $r = Invoke-C2cEnable -DoEnable $true -Scenario 'preexistbothfail'
        $r.AddCalled    | Should Be $false
        $r.EscrowId     | Should Be '{PRE-KP}'
        $r.EntraCalled  | Should Be $true
        $r.AdCalled     | Should Be $true
        $r.RemoveCalled | Should Be $false     # pre-existing protector is never removed
        $r.EnableCalled | Should Be $false
        $r.EncResult    | Should Be 'FAIL'
        $r.EncDetail    | Should Match 'escrow failed \(Entra \+ AD\)'
    }

    It '(c) Entra escrow SUCCEEDS => on-prem AD backup is never called, detail names Entra' {
        $r = Invoke-C2cEnable -DoEnable $true -Scenario 'happy'
        $r.EntraCalled  | Should Be $true
        $r.AdCalled     | Should Be $false
        $r.EnableCalled | Should Be $true
        $r.EncResult    | Should Be 'STARTED'
        $r.EncDetail    | Should Match 'escrowed to Entra'
    }

    It '(d) Entra escrow THROWS => on-prem AD backup is called and succeeds, detail names AD' {
        $r = Invoke-C2cEnable -DoEnable $true -Scenario 'entrafail'
        $r.EntraCalled  | Should Be $true
        $r.AdCalled     | Should Be $true
        $r.EnableCalled | Should Be $true
        $r.EncResult    | Should Be 'STARTED'
        $r.EncDetail    | Should Match 'escrowed to AD'
    }

    It '(e) BOTH escrow paths fail AND we added the protector => Remove called, Enable unreachable, FAIL' {
        $r = Invoke-C2cEnable -DoEnable $true -Scenario 'bothfail'
        $r.AddCalled    | Should Be $true
        $r.EntraCalled  | Should Be $true
        $r.AdCalled     | Should Be $true
        $r.RemoveCalled | Should Be $true      # we added it => remove it
        $r.RemoveIds -contains '{NEW-KP}' | Should Be $true   # the id we resolved at add-time
        $r.EnableCalled | Should Be $false     # enable is unreachable
        $r.EncResult    | Should Be 'FAIL'
        $r.EncDetail    | Should Match 'escrow failed \(Entra \+ AD\) - encryption NOT started'
    }

    It '(e2, v1.15.2) escrow fails AND the added protector id was UNRESOLVABLE => orphan cleanup re-enumerates and removes it, Enable unreachable, FAIL' {
        # The near-impossible edge Opus flagged: Add succeeds but its return carries no
        # resolvable protector id ($newKpId blank). Pre-1.15.2 left the just-added,
        # unescrowed RecoveryPassword protector orphaned on a still-decrypted volume.
        $r = Invoke-C2cEnable -DoEnable $true -Scenario 'bothfailblankid'
        $r.AddCalled    | Should Be $true
        $r.EntraCalled  | Should Be $true
        $r.AdCalled     | Should Be $true
        $r.RemoveCalled | Should Be $true                      # cleanup ran despite the blank id
        $r.RemoveIds -contains '{LATE-KP}' | Should Be $true   # re-enumerated + removed the orphan
        $r.EnableCalled | Should Be $false                     # still fail-closed: no encryption
        $r.EncResult    | Should Be 'FAIL'
        $r.EncDetail    | Should Match 'escrow failed \(Entra \+ AD\) - encryption NOT started'
        $r.Leaked       | Should Be $false                     # recovery password still never leaks
    }

    It '(e3, v1.15.2) the orphan-cleanup path NEVER removes a pre-existing protector (safety)' {
        # A pre-existing RP protector routes to REUSE (no Add, $weAdded=$false), so the
        # cleanup branch is unreachable for it - proven by the pre-existing double-fail
        # case removing nothing at all.
        $r = Invoke-C2cEnable -DoEnable $true -Scenario 'preexistbothfail'
        $r.AddCalled    | Should Be $false
        $r.RemoveCalled | Should Be $false
        ($r.RemoveIds -contains '{PRE-KP}') | Should Be $false
    }

    It '(f) HAPPY PATH order is Policy -> Add -> escrow -> Enable, result STARTED, XtsAes256 full-volume' {
        $r = Invoke-C2cEnable -DoEnable $true -Scenario 'happy'
        $r.EncResult     | Should Be 'STARTED'
        $r.Status        | Should Be 'FIXED'          # STARTED rolls up like FIXED
        $r.EncMethod     | Should Be 'XtsAes256'
        $r.UsedSpaceOnly | Should Be $false           # full-volume (no -UsedSpaceOnly)
        $r.PolicyAsserted | Should Be $true
        # exact call ordering: Policy, then Add, then escrow (Entra), then Enable.
        $order = @($r.Order)
        $iPol = [array]::IndexOf($order, 'Policy')
        $iAdd = [array]::IndexOf($order, 'Add')
        $iEsc = [array]::IndexOf($order, 'Entra')
        $iEn  = [array]::IndexOf($order, 'Enable')
        $iPol | Should Not Be -1
        ($iPol -lt $iAdd) | Should Be $true
        ($iAdd -lt $iEsc) | Should Be $true
        ($iEsc -lt $iEn)  | Should Be $true
    }

    It '(g) HAPPY PATH: the recovery password is NEVER present in the pillar object or report text' {
        $r = Invoke-C2cEnable -DoEnable $true -Scenario 'happy'
        $r.Leaked | Should Be $false
    }

    It '(g2) pre-existing + Entra success: recovery password still never leaks and the pre-existing id is escrowed' {
        $r = Invoke-C2cEnable -DoEnable $true -Scenario 'preexisthappy'
        $r.AddCalled | Should Be $false
        $r.EscrowId  | Should Be '{PRE-KP}'
        $r.EncResult | Should Be 'STARTED'
        $r.Leaked    | Should Be $false
    }

    It '(h) TPM not ready => SKIP enable; FVE GPO policy IS healed (v7.11 parity); no protector, escrow + Enable never called' {
        $r = Invoke-C2cEnable -DoEnable $true -Scenario 'tpmnotready'
        $r.EncResult      | Should Be 'SKIP'
        $r.EncDetail      | Should Match 'TPM not ready'
        # v7.11 full parity: policy asserted once up front, BEFORE the TPM gate SKIPs the enable.
        $r.PolicyAsserted | Should Be $true
        $r.AddCalled      | Should Be $false
        $r.EnableCalled   | Should Be $false
    }

    It '(h) not domain-joined => SKIP enable; FVE GPO policy IS healed (v7.11 parity); no protector, escrow + Enable never called' {
        $r = Invoke-C2cEnable -DoEnable $true -Scenario 'notdomain'
        $r.EncResult      | Should Be 'SKIP'
        $r.EncDetail      | Should Match 'not domain-joined'
        $r.PolicyAsserted | Should Be $true
        $r.AddCalled      | Should Be $false
        $r.EnableCalled   | Should Be $false
    }

    It 'enableEncryption OFF + FullyDecrypted => SKIP routing text (enable NOT attempted) but FVE GPO policy IS healed (v7.11 parity)' {
        $r = Invoke-C2cEnable -DoEnable $false -Scenario 'happy'
        $r.EncResult      | Should Be 'SKIP'
        $r.EncDetail      | Should Match 'route to MECM/desk-side'
        $r.EncDetail      | Should Match 'TPM\+recovery-key escrow policy'
        # The GPO heal is non-destructive and runs whenever the Encryption pillar runs; only the
        # destructive ENABLE stays gated behind enableEncryption. No protector added, no Enable called.
        $r.PolicyAsserted | Should Be $true
        $r.AddCalled      | Should Be $false
        $r.EnableCalled   | Should Be $false
    }
}

# -----------------------------------------------------------------------------
Describe 'C2C manifest - C2C Nemesis v1.10.0, per-pillar fix actions (incl. fix-pki) + run-all + version-check' {

    $man = Get-JanetToolManifest
    $fix = @($man.actions | Where-Object { $_.id -eq 'fix-encryption' })[0]
    $inp = @($fix.inputs | Where-Object { $_.name -eq 'enableEncryption' })[0]
    $mon = @($man.actions | Where-Object { $_.id -eq 'fix-monitoring' })[0]
    $fixIds  = @('fix-monitoring','fix-firewall','fix-antimalware','fix-patches','fix-encryption','fix-pki')
    $destIds = @($fixIds + 'run-all')

    It 'reports the display name C2C Nemesis' {
        $man.name | Should Be 'C2C Nemesis'
    }
    It 'keeps the tool id c2c (routes / registry / log names are unchanged)' {
        $man.id | Should Be 'c2c'
    }
    It 'reports tool version 1.15.2' {
        $man.version | Should Be '1.15.2'
    }
    It 'exposes 12 actions: scan + import + six per-pillar fixes + fix-lockscreen + fix-java + run-all + version-check' {
        @($man.actions).Count | Should Be 12
    }
    It 'has the exact action id set' {
        $ids = @($man.actions | ForEach-Object { $_.id } | Sort-Object)
        $expect = @('fix-antimalware','fix-encryption','fix-firewall','fix-java','fix-lockscreen','fix-monitoring','fix-patches','fix-pki','import','run-all','scan','version-check')
        ($ids -join ',') | Should Be ($expect -join ',')
    }
    It 'has scan + import + version-check (read-only) and all fix-* + run-all (destructive)' {
        (@($man.actions | Where-Object { $_.id -eq 'scan' })[0].destructive)          | Should Be $false
        (@($man.actions | Where-Object { $_.id -eq 'import' })[0].destructive)        | Should Be $false
        (@($man.actions | Where-Object { $_.id -eq 'version-check' })[0].destructive) | Should Be $false
        foreach ($id in $destIds) {
            $a = @($man.actions | Where-Object { $_.id -eq $id })[0]
            $a | Should Not BeNullOrEmpty
            [bool]$a.destructive | Should Be $true
        }
    }
    It 'the legacy monolithic "fix" action id is REMOVED (clean break)' {
        @($man.actions | Where-Object { $_.id -eq 'fix' }).Count | Should Be 0
    }
    It 'the fix-pki action is BACK, with the certBundleFolder input (folder/.cer bundle, not .sst)' {
        $pki = @($man.actions | Where-Object { $_.id -eq 'fix-pki' })[0]
        $pki | Should Not BeNullOrEmpty
        @($pki.inputs | Where-Object { $_.name -eq 'certBundleFolder' }).Count | Should Be 1
    }
    It 'no action declares an sstPath input (the .sst path stays gone; certBundleFolder replaces it)' {
        $withSst = @($man.actions | Where-Object { @($_.inputs | Where-Object { $_.name -eq 'sstPath' }).Count -gt 0 })
        @($withSst).Count | Should Be 0
    }
    It 'version-check declares productMatch (text) + targetVersion (text) + winrmHeal (bool)' {
        $vc = @($man.actions | Where-Object { $_.id -eq 'version-check' })[0]
        @($vc.inputs | Where-Object { $_.name -eq 'productMatch' })[0].type  | Should Be 'text'
        @($vc.inputs | Where-Object { $_.name -eq 'targetVersion' })[0].type | Should Be 'text'
        @($vc.inputs | Where-Object { $_.name -eq 'winrmHeal' })[0].type      | Should Be 'bool'
    }
    It 'run-all declares an optional certBundleFolder + a winrmHeal input' {
        $ra = @($man.actions | Where-Object { $_.id -eq 'run-all' })[0]
        @($ra.inputs | Where-Object { $_.name -eq 'certBundleFolder' }).Count | Should Be 1
        @($ra.inputs | Where-Object { $_.name -eq 'winrmHeal' }).Count        | Should Be 1
    }
    It 'the fix-encryption action declares the enableEncryption input (bool)' {
        $inp | Should Not BeNullOrEmpty
        $inp.type | Should Be 'bool'
    }
    It 'enableEncryption defaults to $false (resume stays the default; enable is opt-in)' {
        [bool]$inp.default | Should Be $false
    }
    It 'run-all declares the plan (textarea) input' {
        $ra = @($man.actions | Where-Object { $_.id -eq 'run-all' })[0]
        $pl = @($ra.inputs | Where-Object { $_.name -eq 'plan' })[0]
        $pl | Should Not BeNullOrEmpty
        $pl.type | Should Be 'textarea'
    }
    It 'the fix-monitoring description states the Tanium SOFTWARE installed (uninstall registry) check' {
        $mon.description | Should Match '(?i)uninstall registry'
        $mon.description | Should Match '(?i)Software Center'
    }
    It 'the fix-encryption description states the FVE-policy + Entra-first/AD-fallback / escrow-first / XtsAes256 enable behaviour' {
        $fix.description | Should Match 'FVE'
        $fix.description | Should Match 'Entra-first'
        $fix.description | Should Match 'ESCROW-FIRST'
        $fix.description | Should Match 'XtsAes256'
        $fix.description | Should Match 'NEVER encrypted'
    }
    It 'the fix-encryption description states the multi-volume (all fixed volumes) + data-volume behaviour' {
        $fix.description | Should Match '(?i)EVERY FIXED VOLUME'
        $fix.description | Should Match '(?i)DATA volume'
        $fix.description | Should Match '(?i)auto-unlock'
        $fix.description | Should Match '(?i)removable'
    }
    It 'the fix-antimalware description states the AMRunningMode / Passive / EDR Block Mode behaviour' {
        $am = @($man.actions | Where-Object { $_.id -eq 'fix-antimalware' })[0]
        $am.description | Should Match 'AMRunningMode'
        $am.description | Should Match '(?i)Passive'
        $am.description | Should Match '(?i)EDR Block Mode'
        $am.description | Should Match '(?i)sigMaxAgeHours'
    }
}
