# =============================================================================
#  FixGuards.Tests.ps1 - Pester 3.4 tests for the DNS-mismatch "wrong box"
#  hard-abort self-guard propagated to the destructive fix-actions:
#    * ACAS reboot   (AcasRebootWorker,  credentialed path)
#    * ACAS update   (AcasUpdateWorker,  remediation/install path)
#    * UPR uninstall (UprWorkerBlock,    permanent-removal path)
#    * WPT maint-lock (WptMaintLockBlock, logon hard-lock path)
#
#  Mirrors Wpt.Guards.Tests.ps1: Invoke-Command (and New-PSSession/Remove-PSSession
#  where the worker opens a session) are shadowed IN MODULE SCOPE so NO real WinRM
#  call ever leaves this box. The remote $env:COMPUTERNAME probe answer is faked to
#  drive the guard. Each test asserts on the returned row/summary:
#    (a) MISMATCH  -> destructive op NOT reached, row reports aborted/skipped.
#    (b) MATCH     -> guard passes, destructive op IS reached (recorder flag set).
#    (c) IPv4 target -> compare skipped even with a mismatching probe answer.
#
#  The probe scriptblock is uniformly '{ $env:COMPUTERNAME }' in every guard, so the
#  shim identifies the probe by its scriptblock TEXT and returns everything else as
#  the (inert) real op. TCP reachability probes inside the session-based workers hit
#  the local box ($env:COMPUTERNAME / 127.0.0.1, both listening on 5985/445 here).
#
#  Run:  Invoke-Pester -Path .\tests\FixGuards.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent

function New-FakeCred {
    New-Object System.Management.Automation.PSCredential('tester', (ConvertTo-SecureString 'x' -AsPlainText -Force))
}

# -----------------------------------------------------------------------------
Describe 'ACAS reboot DNS-mismatch hard-abort (AcasRebootWorker)' {

    $m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Force -PassThru

    function Invoke-AcasReboot {
        param([string]$ProbeName, [string]$Target)
        & $m {
            param($ProbeName, $Target)
            $script:__destr = $false
            function script:Invoke-Command {
                param($ComputerName, $ScriptBlock, $ArgumentList, $ErrorAction, $Credential, $Authentication, $Session, $SessionOption)
                if ($ScriptBlock -and ($ScriptBlock.ToString().Trim() -eq '$env:COMPUTERNAME')) { return $ProbeName }
                $script:__destr = $true
                return 0   # shutdown scriptblock returns $LASTEXITCODE == 0 (accepted)
            }
            try {
                $cred = New-Object System.Management.Automation.PSCredential('tester', (ConvertTo-SecureString 'x' -AsPlainText -Force))
                $out = & $script:AcasRebootWorker -Target $Target -WarnMsg 'test' -Cred $cred
                [pscustomobject]@{ Result = [string]$out; Destr = [bool]$script:__destr }
            } finally { Remove-Item function:script:Invoke-Command -ErrorAction SilentlyContinue }
        } $ProbeName $Target
    }

    It 'MISMATCH: aborts and issues NO reboot when the answering box is not the dialed host' {
        $r = Invoke-AcasReboot -ProbeName 'SOMEOTHERBOX' -Target $env:COMPUTERNAME
        $r.Destr  | Should Be $false
        $r.Result | Should Match 'DNS mismatch'
        $r.Result | Should Match 'ABORTED, no reboot sent'
    }

    It 'MATCH: proceeds to the reboot when the answering box matches the dialed host' {
        $r = Invoke-AcasReboot -ProbeName $env:COMPUTERNAME -Target $env:COMPUTERNAME
        $r.Destr  | Should Be $true
        $r.Result | Should Not Match 'DNS mismatch'
        $r.Result | Should Match 'reboot scheduled'
    }

    It 'IPv4 target: skips the compare (reboots even though the probe would mismatch)' {
        $r = Invoke-AcasReboot -ProbeName 'SOMEOTHERBOX' -Target '127.0.0.1'
        $r.Destr  | Should Be $true
        $r.Result | Should Not Match 'DNS mismatch'
        $r.Result | Should Match 'reboot scheduled'
    }
}

# -----------------------------------------------------------------------------
Describe 'ACAS update DNS-mismatch hard-abort (AcasUpdateWorker)' {

    $m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Force -PassThru

    function Invoke-AcasUpdate {
        param([string]$ProbeName, [string]$Target)
        & $m {
            param($ProbeName, $Target)
            $script:__destr = $false
            function script:New-PSSession { param($ComputerName, $SessionOption, $Authentication, $ErrorAction, $Credential) return ([pscustomobject]@{ Id = 1; Name = 'shim' }) }
            function script:Remove-PSSession { param($Session, $ErrorAction) }
            function script:Invoke-Command {
                param($Session, $ComputerName, $ScriptBlock, $ArgumentList, $ErrorAction, $Credential, $Authentication, $SessionOption)
                if ($ScriptBlock -and ($ScriptBlock.ToString().Trim() -eq '$env:COMPUTERNAME')) { return $ProbeName }
                $script:__destr = $true
                return @{ Update = 'OK'; Pre = $null; Post = $null }
            }
            try {
                $cred = New-Object System.Management.Automation.PSCredential('tester', (ConvertTo-SecureString 'x' -AsPlainText -Force))
                $profiles = @{ 'FakeProf' = @{ Script = { 'did-update' }; Verify = $null } }
                $out = & $script:AcasUpdateWorker -TargetIn $Target -ProfileIn 'FakeProf' -UpdateProfilesTable $profiles -VerifyOnlyIn $false -CredIn $cred -StageSource ''
                [pscustomobject]@{ Result = [string]$out; Destr = [bool]$script:__destr }
            } finally { Remove-Item function:script:Invoke-Command, function:script:New-PSSession, function:script:Remove-PSSession -ErrorAction SilentlyContinue }
        } $ProbeName $Target
    }

    It 'MISMATCH: aborts and runs NO remediation when the answering box is not the dialed host' {
        $r = Invoke-AcasUpdate -ProbeName 'SOMEOTHERBOX' -Target $env:COMPUTERNAME
        $r.Destr  | Should Be $false
        $r.Result | Should Match 'DNS mismatch'
        $r.Result | Should Match 'no remediation run'
    }

    It 'MATCH: runs the remediation when the answering box matches the dialed host' {
        $r = Invoke-AcasUpdate -ProbeName $env:COMPUTERNAME -Target $env:COMPUTERNAME
        $r.Destr  | Should Be $true
        $r.Result | Should Not Match 'DNS mismatch'
    }

    It 'IPv4 target: skips the compare (remediates even though the probe would mismatch)' {
        $r = Invoke-AcasUpdate -ProbeName 'SOMEOTHERBOX' -Target '127.0.0.1'
        $r.Destr  | Should Be $true
        $r.Result | Should Not Match 'DNS mismatch'
    }
}

# -----------------------------------------------------------------------------
Describe 'UPR uninstall DNS-mismatch hard-abort (UprWorkerBlock)' {

    $m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.upr.psm1') -Force -PassThru

    function Invoke-UprUninstall {
        param([string]$ProbeName, [string]$Target)
        & $m {
            param($ProbeName, $Target)
            $script:__destr = $false
            function script:New-PSSession { param($ComputerName, $SessionOption, $Authentication, $ErrorAction, $Credential) return ([pscustomobject]@{ Id = 1; Name = 'shim' }) }
            function script:Remove-PSSession { param($Session, $ErrorAction) }
            function script:Invoke-Command {
                param($Session, $ComputerName, $ScriptBlock, $ArgumentList, $ErrorAction, $Credential, $Authentication, $SessionOption)
                if ($ScriptBlock -and ($ScriptBlock.ToString().Trim() -eq '$env:COMPUTERNAME')) { return $ProbeName }
                if ($ScriptBlock -and ($ScriptBlock.ToString() -match 'UprVerifyPresent')) { return ([pscustomobject]@{ Present = $false }) }   # post-uninstall re-enum: product genuinely gone
                if ($ArgumentList) { $script:__destr = $true; return 'OK (shim removed)' }   # the uninstall call
                # otherwise: the installed-software enumeration -> hand back one removable app
                return @( @{ Name = 'FakeVulnApp'; Version = '1.0'; Publisher = 'x'; Type = 'EXE'; UninstallString = 'C:\x.exe'; QuietUninstall = ''; PSChildName = 'FakeVulnApp' } )
            }
            try {
                $prof = @{ DisplayNameRegex = 'FakeVulnApp'; VersionMaxExclusive = ''; Proven = $true; PluginNameMatch = 'P'; Notes = 'n' }
                $out = & $script:UprWorkerBlock -ConnectTarget $Target -Profiles @($prof) -Cred $null -Auth 'Negotiate' -DoUninstall $true -DryRun $false -RemoveSet $null
                $cand = @($out.Candidates)[0]
                [pscustomobject]@{ Error = [string]$out.Error; CandResult = [string]$cand.Result; Destr = [bool]$script:__destr }
            } finally { Remove-Item function:script:Invoke-Command, function:script:New-PSSession, function:script:Remove-PSSession -ErrorAction SilentlyContinue }
        } $ProbeName $Target
    }

    It 'MISMATCH: aborts and removes NOTHING when the answering box is not the dialed host' {
        $r = Invoke-UprUninstall -ProbeName 'SOMEOTHERBOX' -Target $env:COMPUTERNAME
        $r.Destr      | Should Be $false
        $r.Error      | Should Match 'DNS mismatch'
        $r.Error      | Should Match 'no uninstall performed'
        $r.CandResult | Should Be 'Aborted (DNS mismatch)'
    }

    It 'MATCH: performs the uninstall when the answering box matches the dialed host' {
        $r = Invoke-UprUninstall -ProbeName $env:COMPUTERNAME -Target $env:COMPUTERNAME
        $r.Destr      | Should Be $true
        $r.Error      | Should Not Match 'DNS mismatch'
        $r.CandResult | Should Be 'OK (shim removed)'
    }

    It 'IPv4 target: skips the compare (uninstalls even though the probe would mismatch)' {
        $r = Invoke-UprUninstall -ProbeName 'SOMEOTHERBOX' -Target '127.0.0.1'
        $r.Destr      | Should Be $true
        $r.Error      | Should Not Match 'DNS mismatch'
        $r.CandResult | Should Be 'OK (shim removed)'
    }
}

# -----------------------------------------------------------------------------
Describe 'WPT maintenance-lock DNS-mismatch hard-abort (WptMaintLockBlock)' {

    $m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Force -PassThru

    function Invoke-WptMaintLock {
        param([string]$ProbeName, [string]$Computer)
        & $m {
            param($ProbeName, $Computer)
            $script:__destr = $false
            function script:Invoke-Command {
                param($ComputerName, $ScriptBlock, $ArgumentList, $ErrorAction, $Credential, $Authentication, $SessionOption)
                if ($ScriptBlock -and ($ScriptBlock.ToString().Trim() -eq '$env:COMPUTERNAME')) { return $ProbeName }
                $script:__destr = $true
                return @{ Banner = $true; HardLock = $true; Err = '' }
            }
            try {
                $out = & $script:WptMaintLockBlock -Computer $Computer -Cred $null -Auth 'Default' -Caption 'C' -Message 'M' -HardLock $true
                [pscustomobject]@{ Success = [bool]$out.Success; Mode = [string]$out.Mode; Detail = [string]$out.Detail; Destr = [bool]$script:__destr }
            } finally { Remove-Item function:script:Invoke-Command -ErrorAction SilentlyContinue }
        } $ProbeName $Computer
    }

    It 'MISMATCH: aborts and applies NO lock when the answering box is not the dialed host' {
        $r = Invoke-WptMaintLock -ProbeName 'SOMEOTHERBOX' -Computer $env:COMPUTERNAME
        $r.Destr   | Should Be $false
        $r.Success | Should Be $false
        $r.Detail  | Should Match 'DNS mismatch'
        $r.Detail  | Should Match 'no maintenance lock applied'
    }

    It 'MATCH: applies the hard lock when the answering box matches the dialed host' {
        $r = Invoke-WptMaintLock -ProbeName $env:COMPUTERNAME -Computer $env:COMPUTERNAME
        $r.Destr   | Should Be $true
        $r.Success | Should Be $true
        $r.Detail  | Should Not Match 'DNS mismatch'
    }

    It 'IPv4 target: skips the compare (locks even though the probe would mismatch)' {
        $r = Invoke-WptMaintLock -ProbeName 'SOMEOTHERBOX' -Computer '127.0.0.1'
        $r.Destr   | Should Be $true
        $r.Success | Should Be $true
        $r.Detail  | Should Not Match 'DNS mismatch'
    }
}
