# Pester 3.4. These fixtures replace every network and endpoint read in the probe.
. (Join-Path $PSScriptRoot '_Janet.TestKit.ps1')
$cm = Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'modules\JanetWeb.c2c.psm1') -Force -PassThru

function Invoke-ComplianceFixture {
    param([string]$Scenario)
    $shims = Save-ShimState $cm @('New-Object','New-PSSession','Remove-PSSession','Invoke-Command',
        'Get-MpComputerStatus','Get-Service','Get-ItemProperty','Test-Path','Get-ChildItem',
        'Get-NetFirewallProfile','Get-BitLockerVolume','Get-Volume','Get-AppLockerPolicy',
        'Get-CimInstance','Invoke-CimMethod')
    try {
        & $cm {
            param($Scenario)
            $scenarioData = @{
                Name = $Scenario
                MatchOrg = '00000000-0000-0000-0000-000000000001'
                WrongOrg = '00000000-0000-0000-0000-000000000002'
            }
            function script:New-Object {
                param($TypeName, $ArgumentList)
                # No TCP object is ever constructed. AttemptOffline allows the shim session.
                if ($TypeName -eq 'System.Net.Sockets.TcpClient') { return [pscustomobject]@{ Connected=$false } }
                if ($PSBoundParameters.ContainsKey('ArgumentList')) {
                    Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName -ArgumentList $ArgumentList
                } else { Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName }
            }
            function script:New-PSSession { [pscustomobject]@{ Id=1 } }
            function script:Remove-PSSession {}
            function script:Invoke-Command {
                param($Session,$ScriptBlock,$ArgumentList,$ErrorAction)
                $reply = & $ScriptBlock @ArgumentList
                if ($scenarioData.Name -eq 'wrong-host') { $reply.RemoteName = 'OTHER-FIXTURE' }
                if ($scenarioData.Name -eq 'missing-identity') { $reply.RemoteName = '' }
                if ($scenarioData.Name -notin @('wrong-host','missing-identity')) { $reply.RemoteName = 'COMPLIANCE-FIXTURE' }
                if ($scenarioData.Name -eq 'missing-checks') { $reply.Checks = $null }
                if ($scenarioData.Name -eq 'malformed-time') { $reply.Evidence.ObservedAtUtc = '2026-02-31T03:00:00.0000000Z' }
                if ($scenarioData.Name -eq 'untrusted-evidence') {
                    $reply.Evidence.RawOrgId = $scenarioData.MatchOrg
                    $reply.Evidence.DefenderEnabled = 'true'
                    $reply.Evidence.DefenderRunningMode = $scenarioData.WrongOrg
                    $reply.Evidence.MdeOrgIdStatus = $scenarioData.MatchOrg
                    $reply.Evidence.IntuneEnrollmentStatus = 'Enrolled'
                    $reply.Evidence.ReportingStatus = 'Reporting'
                    $reply.Evidence.SystemDriveFreeGB = [double]::NaN
                    $reply.Evidence.SystemDriveFreePercent = 101
                    $reply.Evidence.DefenderSignatureAgeHours = [double]::PositiveInfinity
                    $reply.Evidence.MecmPendingUpdates = 1
                    $reply.Evidence.MecmOverdueUpdates = 2
                    $reply.Evidence.FirefoxInventoryScope = $scenarioData.WrongOrg
                }
                return $reply
            }
            function script:Get-MpComputerStatus {
                param($ErrorAction)
                $age = if ($scenarioData.Name -eq 'bad') { 168.01 } elseif ($scenarioData.Name -eq 'future') { -2 } else { 167.99 }
                $mp = [pscustomobject]@{
                    AntivirusEnabled = ($scenarioData.Name -ne 'bad')
                    AMRunningMode = 'Normal'
                    RealTimeProtectionEnabled = ($scenarioData.Name -ne 'bad')
                    AntivirusSignatureLastUpdated = [datetime]::UtcNow.AddHours(-$age)
                    AntivirusSignatureAge = 6
                }
                if ($scenarioData.Name -eq 'unknown') {
                    $mp.AntivirusEnabled = $null
                    $mp.AntivirusSignatureLastUpdated = $null
                }
                return $mp
            }
            function script:Get-Service {
                param($Name,$ErrorAction)
                if ($scenarioData.Name -eq 'unknown') { throw [UnauthorizedAccessException]::new() }
                $state = if ($Name -eq 'wuauserv' -or ($Name -eq 'Sense' -and $scenarioData.Name -eq 'bad')) { 'Stopped' } else { 'Running' }
                [pscustomobject]@{ Status=$state }
            }
            function script:Get-ItemProperty {
                param($Path,$LiteralPath,$Name,$ErrorAction)
                if ($Name -eq 'OrgId') {
                    if ($scenarioData.Name -eq 'unknown') { throw [UnauthorizedAccessException]::new() }
                    if ($scenarioData.Name -eq 'future') { return }
                    $id = if ($scenarioData.Name -eq 'bad') { $scenarioData.WrongOrg } else { $scenarioData.MatchOrg }
                    return [pscustomobject]@{ OrgId=$id }
                }
                if ($Name -eq 'ProviderID') { return [pscustomobject]@{ ProviderID='Fixture MDM provider' } }
                if ($Path -match 'WOW6432Node.*Uninstall' -and $scenarioData.Name -eq 'unknown') { throw [UnauthorizedAccessException]::new() }
                if ($Path -match 'Uninstall' -and $scenarioData.Name -eq 'bad') { return [pscustomobject]@{ DisplayName='Mozilla Firefox ESR (x64 en-US)' } }
                if ($Path -match 'CurrentVersion$') { return [pscustomobject]@{ CurrentBuildNumber='26100'; DisplayVersion='24H2'; EditionID='Enterprise' } }
            }
            function script:Test-Path {
                param($LiteralPath,$ErrorAction)
                if ($LiteralPath -match 'Enrollments$') {
                    if ($scenarioData.Name -eq 'unknown') { throw [UnauthorizedAccessException]::new() }
                    return ($scenarioData.Name -ne 'bad')
                }
                if ($LiteralPath -match 'Uninstall$') { return $true }
                return ($scenarioData.Name -eq 'bad' -and $LiteralPath -match 'RebootPending$')
            }
            function script:Get-ChildItem {
                param($LiteralPath,$ErrorAction)
                [pscustomobject]@{ PSChildName='00000000-0000-0000-0000-000000000003'; PSPath='fixture' }
            }
            function script:Get-NetFirewallProfile { foreach ($p in 'Domain','Private','Public') { [pscustomobject]@{ Name=$p; Enabled=$true } } }
            function script:Get-BitLockerVolume { [pscustomobject]@{ VolumeType='OperatingSystem'; MountPoint=$env:SystemDrive; ProtectionStatus='On'; VolumeStatus='FullyEncrypted' } }
            function script:Get-Volume { [pscustomobject]@{ DriveType='Fixed'; DriveLetter=$env:SystemDrive.Substring(0,1) } }
            function script:Get-AppLockerPolicy { [pscustomobject]@{ RuleCollections=@([pscustomobject]@{ EnforcementMode='Enabled' }) } }
            function script:Get-CimInstance {
                param($Query,$Namespace,$ClassName,$Filter,$ErrorAction)
                if ($scenarioData.Name -eq 'unknown') { throw [UnauthorizedAccessException]::new() }
                if ($ClassName -eq 'Win32_LogicalDisk') {
                    $free = if ($scenarioData.Name -eq 'bad') { 0 } else { 12GB }
                    return [pscustomobject]@{ FreeSpace=$free; Size=60GB }
                }
                if ($Query -match 'CCM_SoftwareUpdate' -and $scenarioData.Name -ne 'bad') {
                    [pscustomobject]@{ Deadline=[datetime]::UtcNow.AddDays(-1) }
                    [pscustomobject]@{ Deadline=[datetime]::UtcNow.AddDays(1) }
                }
            }
            function script:Invoke-CimMethod {
                if ($scenarioData.Name -eq 'unknown') { throw [UnauthorizedAccessException]::new() }
                [pscustomobject]@{ ReturnValue=0; RebootPending=$false; IsHardRebootPending=$false }
            }
            $config = Get-C2cBaselineDefaults
            $config['mdeOrgId'] = $scenarioData.MatchOrg
            & $script:C2cProbeBlock 'COMPLIANCE-FIXTURE' $null 'Default' $true $config $script:C2cTaniumInstalledSrc $script:C2cVerdictSrc
        } $Scenario
    } finally { Restore-ShimState $cm $shims }
}

Describe 'C2C v1.19.0 read-only compliance evidence' {
    It 'adds evidence without creating a write action' {
        $manifest = & $cm { Get-JanetToolManifest }
        $manifest.version | Should Be '1.19.0'
        ($manifest.actions | Where-Object { $_.id -eq 'scan' }).destructive | Should Be $false
    }

    It 'emits typed local facts and leaves external signals external' {
        $r = Invoke-ComplianceFixture 'healthy'
        $r.Rules.Count | Should Be 11
        $r.Rules.Firewall.Status | Should Be 'PASS'
        $r.Rules.PkiRoots.Tier | Should Be 'Audit'
        $r.Rules.Vuln.Status | Should Be 'EXT'
        $r.Evidence.ObservedAtUtc | Should Match 'Z$'
        $r.Evidence.DefenderEnabled | Should Be $true
        $r.Evidence.DefenderRealTimeProtectionEnabled | Should Be $true
        ($r.Evidence.DefenderSignatureAgeHours -gt 167.98 -and $r.Evidence.DefenderSignatureAgeHours -lt 168) | Should Be $true
        $r.Evidence.MdeOrgIdStatus | Should Be 'Match'
        $r.Evidence.MdeSenseRunning | Should Be $true
        $r.Evidence.ReportingStatus | Should Be 'Unknown'
        $r.Evidence.LocalMdmEnrollmentEvidence | Should Be 'Present'
        $r.Evidence.IntuneEnrollmentStatus | Should Be 'Unknown'
        $r.Evidence.SystemDriveFreeGB | Should Be 12
        $r.Evidence.SystemDriveFreePercent | Should Be 20
        $r.Evidence.MecmPendingUpdates | Should Be 2
        $r.Evidence.MecmOverdueUpdates | Should Be 1
        $r.Evidence.MecmClientRunning | Should Be $true
        $r.Evidence.WindowsUpdateServiceStatus | Should Be 'Stopped'
        $r.Evidence.RebootPending | Should Be $false
        $r.Evidence.FirefoxInstalled | Should Be $false
        $r.Evidence.FirefoxInventoryScope | Should Be 'Machine uninstall registry'
    }

    It 'retains observed false, zero, and a prohibited install without exposing tenant IDs' {
        $r = Invoke-ComplianceFixture 'bad'
        $r.Evidence.DefenderEnabled | Should Be $false
        ($r.Evidence.DefenderSignatureAgeHours -gt 168 -and $r.Evidence.DefenderSignatureAgeHours -lt 168.03) | Should Be $true
        $r.Evidence.MdeOrgIdStatus | Should Be 'Wrong'
        $r.Evidence.MdeSenseRunning | Should Be $false
        $r.Evidence.LocalMdmEnrollmentEvidence | Should Be 'Absent'
        $r.Evidence.SystemDriveFreeGB | Should Be 0
        $r.Evidence.MecmPendingUpdates | Should Be 0
        $r.Evidence.RebootPending | Should Be $true
        $r.Evidence.FirefoxInstalled | Should Be $true
        $r.Status | Should Be 'QUARANTINE RISK'
        ($r | ConvertTo-Json -Depth 8) | Should Not Match '00000000-0000-0000-0000-00000000000[12]'
    }

    It 'leaves denied reads and day-only age evidence unknown' {
        $r = Invoke-ComplianceFixture 'unknown'
        $r.Evidence.MdeOrgIdStatus | Should Be 'Unknown'
        $r.Evidence.LocalMdmEnrollmentEvidence | Should Be 'Unknown'
        foreach ($field in 'DefenderEnabled','DefenderSignatureAgeHours','MdeSenseRunning','SystemDriveFreeGB',
            'MecmPendingUpdates','MecmOverdueUpdates','MecmClientRunning','BitsServiceStatus','RebootPending','FirefoxInstalled') {
            ($null -eq $r.Evidence[$field]) | Should Be $true
        }
        $r.Rules.Patches.Status | Should Be 'ERROR'
    }

    It 'treats future signatures as unknown and distinguishes a missing Org ID from access denial' {
        $r = Invoke-ComplianceFixture 'future'
        ($null -eq $r.Evidence.DefenderSignatureAgeHours) | Should Be $true
        $r.Evidence.MdeOrgIdStatus | Should Be 'Missing'
    }

    It 'suppresses structured evidence for mismatched or missing remote identity' {
        foreach ($scenario in 'wrong-host','missing-identity') {
            $r = Invoke-ComplianceFixture $scenario
            ($r.Status -in @('DNS MISMATCH','IDENTITY UNKNOWN')) | Should Be $true
            $r.ContainsKey('Evidence') | Should Be $false
            $r.ContainsKey('Rules') | Should Be $false
        }
    }

    It 'rejects malformed or out-of-range evidence from the remoting reply' {
        $r = Invoke-ComplianceFixture 'untrusted-evidence'
        $r.Evidence.ContainsKey('RawOrgId') | Should Be $false
        $r.Evidence.MdeOrgIdStatus | Should Be 'Unknown'
        $r.Evidence.IntuneEnrollmentStatus | Should Be 'Unknown'
        $r.Evidence.ReportingStatus | Should Be 'Unknown'
        $r.Evidence.FirefoxInventoryScope | Should Be 'Machine uninstall registry'
        foreach ($field in 'DefenderEnabled','DefenderRunningMode','DefenderSignatureAgeHours',
            'SystemDriveFreeGB','SystemDriveFreePercent','MecmOverdueUpdates') {
            ($null -eq $r.Evidence[$field]) | Should Be $true
        }
        $r.Evidence.MecmPendingUpdates | Should Be 1
    }

    It 'omits evidence on malformed timestamps and failed probes' {
        $r = Invoke-ComplianceFixture 'malformed-time'
        $r.ContainsKey('Evidence') | Should Be $false
        $r = Invoke-ComplianceFixture 'missing-checks'
        $r.Status | Should Be 'ERROR'
        $r.ContainsKey('Evidence') | Should Be $false
        $r.ContainsKey('Rules') | Should Be $false
    }

    It 'includes the same structured evidence in the streamed row and final result' {
        $actual = & $cm {
            $oldWorker = $script:C2cProbeBlock
            $oldBaseline = (Get-Item function:Get-C2cBaseline).ScriptBlock
            try {
                # Pool worker has no module scope. This stub emits one identified scan result.
                $script:C2cProbeBlock = {
                    param($Computer)
                    @{
                        Host=$Computer; Ping='TCP fixture'; Status='READY'; Detail='fixture'; Report=''
                        Rules=@{ Patches=@{ Status='PASS'; Tier='Quarantine' } }
                        Evidence=@{ MecmPendingUpdates=0; DefenderEnabled=$false }
                    }
                }
                function script:Get-C2cBaseline {
                    @{ Source='fixture'; Config=@{ dodRootThumbprints=@('fixture') } }
                }
                $events = [System.Collections.Generic.List[object]]::new()
                $result = Invoke-JanetToolAction -ActionId scan -Params @{ targets='COMPLIANCE-FIXTURE'; threads=1 } -Emit {
                    param($event)
                    $events.Add($event)
                }
                @{
                    Row = @($events | Where-Object { $_.type -eq 'row' -and $_.Status -eq 'READY' })[0]
                    Result = $result
                }
            } finally {
                $script:C2cProbeBlock = $oldWorker
                Set-Item function:script:Get-C2cBaseline -Value $oldBaseline
            }
        }
        $actual.Row.Rules.Patches.Status | Should Be 'PASS'
        $actual.Row.Evidence.DefenderEnabled | Should Be $false
        $actual.Result.rows[0].Evidence.MecmPendingUpdates | Should Be 0
        $actual.Result.rows[0].Rules.Patches.Tier | Should Be 'Quarantine'
        $actual.Result.summary.ready | Should Be 1
    }
}
