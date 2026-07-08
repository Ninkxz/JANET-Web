# =============================================================================
#  C2c.Enable.Tests.ps1 - Pester 3.4 tests for the C2C Mass Fix v1.2.0 opt-in
#  BitLocker ENABLE path (Encryption pillar). Proves ESCROW-FIRST / FAIL-CLOSED
#  behaviour by driving the module-scoped per-host worker ($script:C2cFixBlock)
#  with the suite's shim idiom: New-PSSession / Remove-PSSession / Invoke-Command
#  and every BitLocker/TPM/CIM cmdlet are shadowed IN MODULE SCOPE, so the enable
#  logic runs LOCALLY against fakes and NO WinRM call ever leaves this box.
#
#  The shimmed Invoke-Command EXECUTES the remote fix scriptblock locally
#  (& $ScriptBlock @ArgumentList) against the shimmed cmdlets, which is how the
#  Add -> Backup -> Enable order and the recovery-password redaction are observed.
#
#  Run:  Invoke-Pester -Path .\tests\C2c.Enable.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$cm = Import-Module (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1') -Force -PassThru

# Drive the per-host worker with mocked cmdlets. $Scenario tunes the fakes:
#   happy | escrowfail | tpmnotready | notdomain
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
                return [pscustomobject]@{ ProtectionStatus = 'Off'; VolumeStatus = 'FullyDecrypted'; VolumeType = 'OperatingSystem'; EncryptionPercentage = 0; KeyProtector = @() }
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
        function script:Add-BitLockerKeyProtector {
            param($MountPoint, [switch]$RecoveryPasswordProtector, $ErrorAction)
            [void]$script:__order.Add('Add')
            return [pscustomobject]@{ KeyProtector = @([pscustomobject]@{ KeyProtectorType = 'RecoveryPassword'; KeyProtectorId = '{NEW-KP}'; RecoveryPassword = $script:__sentinel }) }
        }
        function script:Backup-BitLockerKeyProtector {
            param($MountPoint, $KeyProtectorId, $ErrorAction)
            [void]$script:__order.Add('Backup')
            if ($script:__scenario -eq 'escrowfail') { throw 'AD backup RPC failed' }
        }
        function script:Remove-BitLockerKeyProtector {
            param($MountPoint, $KeyProtectorId, $ErrorAction)
            [void]$script:__order.Add('Remove')
        }
        function script:Enable-BitLocker {
            param($MountPoint, [switch]$TpmProtector, $EncryptionMethod, [switch]$SkipHardwareTest, [switch]$UsedSpaceOnly, $ErrorAction)
            [void]$script:__order.Add('Enable')
            $script:__encMethod = [string]$EncryptionMethod
            $script:__usedSpace = [bool]$UsedSpaceOnly
        }

        try {
            # target = self so the wrong-box guard passes (answering box == dialed short name).
            $res = & $script:C2cFixBlock $env:COMPUTERNAME $null 'Default' $true $true $false $false $false $DoEnable ''
            $pillars = @($res.Pillars)
            $enc = @($pillars | Where-Object { $_.Name -eq 'Encryption' })
            $blob = ''
            foreach ($p in $pillars) { $blob += ('|' + [string]$p.Name + '|' + [string]$p.Result + '|' + [string]$p.Detail) }
            $blob += ('|' + [string]$res.Detail + '|' + [string]$res.Report)
            [pscustomobject]@{
                Status        = [string]$res.Status
                EncResult     = $(if ($enc.Count) { [string]$enc[0].Result } else { '' })
                EncDetail     = $(if ($enc.Count) { [string]$enc[0].Detail } else { '' })
                Report        = [string]$res.Report
                Order         = @($script:__order.ToArray())
                AddCalled     = (@($script:__order) -contains 'Add')
                BackupCalled  = (@($script:__order) -contains 'Backup')
                RemoveCalled  = (@($script:__order) -contains 'Remove')
                EnableCalled  = (@($script:__order) -contains 'Enable')
                EncMethod     = [string]$script:__encMethod
                UsedSpaceOnly = [bool]$script:__usedSpace
                Leaked        = [bool]($blob -match [regex]::Escape($script:__sentinel))
            }
        } finally {
            Remove-Item function:script:New-PSSession, function:script:Remove-PSSession, function:script:Invoke-Command, `
                function:script:Get-BitLockerVolume, function:script:Get-Tpm, function:script:Get-CimInstance, `
                function:script:Add-BitLockerKeyProtector, function:script:Backup-BitLockerKeyProtector, `
                function:script:Remove-BitLockerKeyProtector, function:script:Enable-BitLocker -ErrorAction SilentlyContinue
        }
    } $DoEnable $Scenario
}

# -----------------------------------------------------------------------------
Describe 'C2C Mass Fix v1.2.0 - opt-in BitLocker ENABLE (escrow-first, fail-closed)' {

    It '(a) escrow (Backup) FAILS => Enable-BitLocker NEVER called, protector removed, result FAIL' {
        $r = Invoke-C2cEnable -DoEnable $true -Scenario 'escrowfail'
        $r.AddCalled    | Should Be $true
        $r.BackupCalled | Should Be $true
        $r.RemoveCalled | Should Be $true
        $r.EnableCalled | Should Be $false
        $r.EncResult    | Should Be 'FAIL'
        $r.EncDetail    | Should Match 'AD escrow failed - encryption NOT started'
    }

    It '(b) TPM not ready => SKIP, no protector added, Enable never called' {
        $r = Invoke-C2cEnable -DoEnable $true -Scenario 'tpmnotready'
        $r.EncResult    | Should Be 'SKIP'
        $r.EncDetail    | Should Match 'TPM not ready'
        $r.AddCalled    | Should Be $false
        $r.EnableCalled | Should Be $false
    }

    It '(c) not domain-joined => SKIP, no protector added, Enable never called' {
        $r = Invoke-C2cEnable -DoEnable $true -Scenario 'notdomain'
        $r.EncResult    | Should Be 'SKIP'
        $r.EncDetail    | Should Match 'not domain-joined'
        $r.AddCalled    | Should Be $false
        $r.EnableCalled | Should Be $false
    }

    It '(d) REGRESSION: enableEncryption OFF + FullyDecrypted => today''s SKIP routing text (nothing changed)' {
        $r = Invoke-C2cEnable -DoEnable $false -Scenario 'happy'
        $r.EncResult    | Should Be 'SKIP'
        $r.EncDetail    | Should Match 'route to MECM/desk-side'
        $r.EncDetail    | Should Match 'TPM\+recovery-key escrow policy'
        $r.AddCalled    | Should Be $false
        $r.EnableCalled | Should Be $false
    }

    It '(e) HAPPY PATH: call order is Add -> Backup -> Enable, result STARTED, XtsAes256 full-volume' {
        $r = Invoke-C2cEnable -DoEnable $true -Scenario 'happy'
        $r.EncResult    | Should Be 'STARTED'
        $r.Status       | Should Be 'FIXED'          # STARTED rolls up like FIXED
        $r.EnableCalled | Should Be $true
        $r.RemoveCalled | Should Be $false
        $r.EncMethod    | Should Be 'XtsAes256'
        $r.UsedSpaceOnly | Should Be $false          # full-volume (no -UsedSpaceOnly)
        # exact call ordering: Add, then Backup, then Enable.
        $order = @($r.Order)
        $iAdd = [array]::IndexOf($order, 'Add')
        $iBak = [array]::IndexOf($order, 'Backup')
        $iEn  = [array]::IndexOf($order, 'Enable')
        $iAdd | Should Not Be -1
        ($iAdd -lt $iBak) | Should Be $true
        ($iBak -lt $iEn)  | Should Be $true
    }

    It '(e) HAPPY PATH: the recovery password is NEVER present in the pillar object or report text' {
        $r = Invoke-C2cEnable -DoEnable $true -Scenario 'happy'
        $r.Leaked | Should Be $false
    }
}

# -----------------------------------------------------------------------------
Describe 'C2C manifest - fix action exposes enableEncryption (default off), version 1.2.0' {

    $man = Get-JanetToolManifest
    $fix = @($man.actions | Where-Object { $_.id -eq 'fix' })[0]
    $inp = @($fix.inputs | Where-Object { $_.name -eq 'enableEncryption' })[0]

    It 'reports tool version 1.2.0' {
        $man.version | Should Be '1.2.0'
    }
    It 'the fix action declares the enableEncryption input' {
        $inp | Should Not BeNullOrEmpty
        $inp.type | Should Be 'bool'
    }
    It 'enableEncryption defaults to $false (resume stays the default; enable is opt-in)' {
        [bool]$inp.default | Should Be $false
    }
    It 'the fix description states the escrow-first / XtsAes256 / TPM-gated enable behaviour' {
        $fix.description | Should Match 'ESCROW-FIRST'
        $fix.description | Should Match 'XtsAes256'
        $fix.description | Should Match 'never started'
    }
}
