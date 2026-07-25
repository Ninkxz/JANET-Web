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
# -----------------------------------------------------------------------------
# Shim hygiene (audit 2026-07-25). Every shim teardown in this file used to be spelled
# 'Remove-Item function:script:<name>'. That spelling is INERT: the function provider has no
# scope qualifier in its paths, so 'function:script:X' names an item that does not exist and
# the -ErrorAction SilentlyContinue swallowed the failure - the shim SURVIVED into every later
# Describe/It in the file, where a test could then pass on a leaked stub. The naive correction
# ('Remove-Item function:X') is worse when the shim shadows a MODULE function: it deletes the
# real one. So snapshot first, then put back exactly what was there - the captured ScriptBlock
# for a module function, or nothing at all for a shimmed CMDLET (which had no function entry
# to begin with, and whose shim the unqualified path does remove).
function Add-ShimGuard {
    param($Mod)
    & $Mod {
        function script:Save-ShimState {
            param([string[]]$Names)
            $h = @{}
            foreach ($n in $Names) {
                $i = Get-Item -LiteralPath "function:$n" -ErrorAction SilentlyContinue
                if ($i) { $h[$n] = $i.ScriptBlock } else { $h[$n] = $null }
            }
            return $h
        }
        function script:Restore-ShimState {
            param($State)
            foreach ($k in @($State.Keys)) {
                if ($State[$k]) { Set-Item -LiteralPath "function:script:$k" -Value $State[$k] }
                else { Remove-Item -LiteralPath "function:$k" -ErrorAction SilentlyContinue }
            }
        }
    }
}
# -----------------------------------------------------------------------------

function New-FakeCred {
    New-Object System.Management.Automation.PSCredential('tester', (ConvertTo-SecureString 'x' -AsPlainText -Force))
}

# -----------------------------------------------------------------------------
Describe 'ACAS reboot DNS-mismatch hard-abort (AcasRebootWorker)' {

    $m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Force -PassThru
    Add-ShimGuard $m

    function Invoke-AcasReboot {
        param([string]$ProbeName, [string]$Target)
        & $m {
            param($ProbeName, $Target)
            $script:__destr = $false
            $__shims = Save-ShimState @('Invoke-Command')
            function script:Invoke-Command {
                param($ComputerName, $ScriptBlock, $ArgumentList, $ErrorAction, $Credential, $Authentication, $Session, $SessionOption)
                if ($ScriptBlock -and ($ScriptBlock.ToString().Trim() -eq '$env:COMPUTERNAME')) { return $ProbeName }   # ambient-path standalone probe (still in the module)
                # audit 2026-07-23: harness updated for the folded guard - the credentialed
                # path now runs the compare INSIDE the shutdown scriptblock and answers with
                # a JANET_DNS_MISMATCH:<name> sentinel. The real block's tail is a hard-coded
                # local shutdown.exe (cannot execute it here), so the shim plays the REMOTE
                # box instead: answer as a machine named $ProbeName against the $expectShort
                # the worker wired into -ArgumentList (arg 1), per the block's sentinel
                # contract - assertions unchanged.
                if ($ScriptBlock -and ($ScriptBlock.ToString() -match 'JANET_DNS_MISMATCH')) {
                    $expectShort = [string]$ArgumentList[1]
                    if ($expectShort -and (([string]$ProbeName).Trim().ToUpper() -ne $expectShort.Trim().ToUpper())) {
                        return "JANET_DNS_MISMATCH:$ProbeName"
                    }
                }
                $script:__destr = $true
                return 0   # shutdown scriptblock returns $LASTEXITCODE == 0 (accepted)
            }
            try {
                $cred = New-Object System.Management.Automation.PSCredential('tester', (ConvertTo-SecureString 'x' -AsPlainText -Force))
                $out = & $script:AcasRebootWorker -Target $Target -WarnMsg 'test' -Cred $cred
                [pscustomobject]@{ Result = [string]$out; Destr = [bool]$script:__destr }
            } finally { Restore-ShimState $__shims }   # audit 2026-07-25: the old 'Remove-Item function:script:X' spelling was inert (see Add-ShimGuard) - the shim leaked
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
    Add-ShimGuard $m

    function Invoke-AcasUpdate {
        param([string]$ProbeName, [string]$Target)
        & $m {
            param($ProbeName, $Target)
            $script:__destr = $false
            $__shims = Save-ShimState @('New-PSSession','Remove-PSSession','Invoke-Command')
            function script:New-PSSession { param($ComputerName, $SessionOption, $Authentication, $ErrorAction, $Credential) return ([pscustomobject]@{ Id = 1; Name = 'shim' }) }
            function script:Remove-PSSession { param($Session, $ErrorAction) }
            function script:Invoke-Command {
                param($Session, $ComputerName, $ScriptBlock, $ArgumentList, $ErrorAction, $Credential, $Authentication, $SessionOption)
                # audit 2026-07-23: harness updated for the folded guard - the standalone
                # probe is gone; the combined scriptblock (identified by its JANET_PROBE_ERR
                # sentinel text) runs the compare as its FIRST statement and returns
                # @{Abort=...} on a wrong box. EXECUTE the real block with $env:COMPUTERNAME
                # faked to the probe answer, so the module's own in-block compare and Abort
                # contract are exercised; the fake profile Script below sets the destructive
                # recorder flag only when the update text actually runs. Assertions unchanged.
                if ($ScriptBlock -and ($ScriptBlock.ToString() -match 'JANET_PROBE_ERR')) {
                    $__oldName = $env:COMPUTERNAME
                    try { $env:COMPUTERNAME = $ProbeName; return (& $ScriptBlock @ArgumentList) }
                    finally { $env:COMPUTERNAME = $__oldName }
                }
                return $null
            }
            try {
                $cred = New-Object System.Management.Automation.PSCredential('tester', (ConvertTo-SecureString 'x' -AsPlainText -Force))
                $profiles = @{ 'FakeProf' = @{ Script = { $script:__destr = $true; 'did-update' }; Verify = $null } }
                $out = & $script:AcasUpdateWorker -TargetIn $Target -ProfileIn 'FakeProf' -UpdateProfilesTable $profiles -VerifyOnlyIn $false -CredIn $cred -StageSource ''
                [pscustomobject]@{ Result = [string]$out; Destr = [bool]$script:__destr }
            } finally { Restore-ShimState $__shims }   # audit 2026-07-25: the old 'Remove-Item function:script:X' spelling was inert (see Add-ShimGuard) - the shim leaked
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
    Add-ShimGuard $m

    function Invoke-UprUninstall {
        param([string]$ProbeName, [string]$Target)
        & $m {
            param($ProbeName, $Target)
            $script:__destr = $false
            $__shims = Save-ShimState @('New-PSSession','Remove-PSSession','Invoke-Command')
            function script:New-PSSession { param($ComputerName, $SessionOption, $Authentication, $ErrorAction, $Credential) return ([pscustomobject]@{ Id = 1; Name = 'shim' }) }
            function script:Remove-PSSession { param($Session, $ErrorAction) }
            function script:Invoke-Command {
                param($Session, $ComputerName, $ScriptBlock, $ArgumentList, $ErrorAction, $Credential, $Authentication, $SessionOption)
                if ($ScriptBlock -and ($ScriptBlock.ToString() -match 'UprVerifyPresent')) { return ([pscustomobject]@{ Present = $false }) }   # post-uninstall re-enum: product genuinely gone
                if ($ArgumentList) { $script:__destr = $true; return 'OK (shim removed)' }   # the uninstall call
                # otherwise: the installed-software enumeration -> hand back one removable app.
                # audit 2026-07-23: harness updated for the folded guard - the standalone probe
                # is gone; the enumeration now ALSO returns the answering box's ComputerName
                # (simulated as $ProbeName) and the worker compares it admin-side. Apps carries
                # what the old shim returned. Assertions unchanged.
                return @{ ComputerName = $ProbeName; Apps = @( @{ Name = 'FakeVulnApp'; Version = '1.0'; Publisher = 'x'; Type = 'EXE'; UninstallString = 'C:\x.exe'; QuietUninstall = ''; PSChildName = 'FakeVulnApp' } ) }
            }
            try {
                $prof = @{ DisplayNameRegex = 'FakeVulnApp'; VersionMaxExclusive = ''; Proven = $true; PluginNameMatch = 'P'; Notes = 'n' }
                $out = & $script:UprWorkerBlock -ConnectTarget $Target -Profiles @($prof) -Cred $null -Auth 'Negotiate' -DoUninstall $true -DryRun $false -RemoveSet $null
                $cand = @($out.Candidates)[0]
                [pscustomobject]@{ Error = [string]$out.Error; CandResult = [string]$cand.Result; Destr = [bool]$script:__destr }
            } finally { Restore-ShimState $__shims }   # audit 2026-07-25: the old 'Remove-Item function:script:X' spelling was inert (see Add-ShimGuard) - the shim leaked
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
    Add-ShimGuard $m

    function Invoke-WptMaintLock {
        param([string]$ProbeName, [string]$Computer)
        & $m {
            param($ProbeName, $Computer)
            $script:__destr = $false
            $__shims = Save-ShimState @('Invoke-Command')
            function script:Invoke-Command {
                param($ComputerName, $ScriptBlock, $ArgumentList, $ErrorAction, $Credential, $Authentication, $SessionOption)
                # audit 2026-07-23: harness updated for the folded guard - the standalone
                # probe is gone; the compare is now the FIRST statement of the block's single
                # working Invoke-Command (-ArgumentList: Caption, Message, HardLock,
                # targetShort, isIPv4) and answers @{DnsMismatch=<name>} on a wrong box. The
                # real block writes the logon banner + a secedit hard-lock (cannot execute it
                # here), so the shim plays the REMOTE box instead: answer as a machine named
                # $ProbeName per the block's DnsMismatch contract. Assertions unchanged.
                if ($ScriptBlock -and ($ScriptBlock.ToString() -match 'DnsMismatch')) {
                    $expected = [string]$ArgumentList[3]; $isIPv4 = [bool]$ArgumentList[4]
                    if (-not $isIPv4 -and $expected -and (([string]$ProbeName).Trim().ToUpper() -ne $expected.Trim().ToUpper())) {
                        return @{ DnsMismatch = $ProbeName }
                    }
                }
                $script:__destr = $true
                return @{ Banner = $true; HardLock = $true; Err = '' }
            }
            try {
                $out = & $script:WptMaintLockBlock -Computer $Computer -Cred $null -Auth 'Default' -Caption 'C' -Message 'M' -HardLock $true
                [pscustomobject]@{ Success = [bool]$out.Success; Mode = [string]$out.Mode; Detail = [string]$out.Detail; Destr = [bool]$script:__destr }
            } finally { Restore-ShimState $__shims }   # audit 2026-07-25: the old 'Remove-Item function:script:X' spelling was inert (see Add-ShimGuard) - the shim leaked
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
