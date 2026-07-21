# =============================================================================
#  FixVerify2.Tests.ps1 - Pester 3.4 tests for the second wave of "reports success
#  without verifying" fixes. Each proves SUCCESS IS GATED on the client's actual
#  result / a read-back, and that a rejected/failed sub-call is NOT counted as
#  success (happy path unchanged).
#
#    FIX 1  MECM InstallUpdates / CCM_Application.Install ReturnValue is captured;
#           a non-zero ReturnValue no longer reports "Triggered" (wpt + acas kb-install).
#    FIX 2  WinUpgrade Pin re-reads the policy and reports DONE only on a match;
#           Unpin re-checks the three pin value names are actually gone.
#    FIX 3  Secure Boot Lenovo compares the post-write read-back to the intended
#           state (like Dell), not just the WMI return string.
#
#  All cmdlets that would leave this box (Invoke-Command / New-PSSession /
#  Get-WmiObject / Invoke-WmiMethod) are shadowed IN MODULE SCOPE. No live host is
#  touched (the KB-install workers probe TCP 5985/445 on THIS box only).
#
#  Run:  Invoke-Pester -Path .\tests\FixVerify2.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent

# -----------------------------------------------------------------------------
Describe 'FIX 1 - MECM InstallUpdates ReturnValue gates "Triggered" (kb-install)' {

    $wm = Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1')  -Force -PassThru
    $am = Import-Module (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Force -PassThru

    # Drive the REAL kb-install worker with Invoke-Command shadowed so the inner MECM
    # scriptblock (the one that now captures .ReturnValue) EXECUTES locally against a
    # shimmed Get-WmiObject/Invoke-WmiMethod. The shim feeds a canned pending update and
    # a chosen ReturnValue, so the worker's real gating logic runs on synthetic data.
    function Invoke-WptKb {
        param([int]$Rv)
        & $wm {
            param($Rv)
            $script:__rv = $Rv
            function script:New-PSSession { param($ComputerName,$SessionOption,$ErrorAction,$Credential,$Authentication) [pscustomobject]@{ Id=1; Name='shim' } }
            function script:Remove-PSSession { [CmdletBinding()] param($Session) }
            function script:Get-WmiObject { [CmdletBinding()] param($Namespace,$Query,$Class,$Name,$ArgumentList) [pscustomobject]@{ Name='KB5031234 Security Update'; ArticleID='5031234' } }
            function script:Invoke-WmiMethod { [CmdletBinding()] param($Class,$Name,$ArgumentList,$Namespace) if ($script:__rv -eq -1) { [pscustomobject]@{} } else { [pscustomobject]@{ ReturnValue = $script:__rv } } }
            function script:Invoke-Command {
                [CmdletBinding()] param($Session,$ComputerName,$ScriptBlock,$ArgumentList,$Credential,$Authentication,$SessionOption)
                $t = if ($ScriptBlock) { $ScriptBlock.ToString() } else { '' }
                if ($t.Trim() -eq '$env:COMPUTERNAME') { return $env:COMPUTERNAME }
                if ($t -match 'CCM_SoftwareUpdate' -and $t -match 'InstallUpdates') { return (& $ScriptBlock @ArgumentList) }
                return $null
            }
            try {
                $out = & $script:WptKbInstallBlock -Computer $env:COMPUTERNAME -Cred $null -Auth 'Negotiate' -KBs @('KB5031234') -MsuPath '' -NoReboot $true
                [pscustomobject]@{ MECMFound=[int]$out.MECMFound; MECMInstalled=[int]$out.MECMInstalled; Errors=(@($out.Errors) -join ' | ') }
            } finally {
                Remove-Item function:script:New-PSSession, function:script:Remove-PSSession, function:script:Get-WmiObject, function:script:Invoke-WmiMethod, function:script:Invoke-Command -EA SilentlyContinue
            }
        } $Rv
    }

    function Invoke-AcasKb {
        param([int]$Rv)
        & $am {
            param($Rv)
            $script:__rv = $Rv
            function script:New-PSSession { param($ComputerName,$SessionOption,$ErrorAction,$Credential,$Authentication) [pscustomobject]@{ Id=1; Name='shim' } }
            function script:Remove-PSSession { [CmdletBinding()] param($Session) }
            function script:Get-WmiObject { [CmdletBinding()] param($Namespace,$Query,$Class,$Name,$ArgumentList) [pscustomobject]@{ Name='KB5031234 Security Update'; ArticleID='5031234' } }
            function script:Invoke-WmiMethod { [CmdletBinding()] param($Class,$Name,$ArgumentList,$Namespace) if ($script:__rv -eq -1) { [pscustomobject]@{} } else { [pscustomobject]@{ ReturnValue = $script:__rv } } }
            function script:Invoke-Command {
                [CmdletBinding()] param($Session,$ComputerName,$ScriptBlock,$ArgumentList,$Credential,$Authentication,$SessionOption)
                $t = if ($ScriptBlock) { $ScriptBlock.ToString() } else { '' }
                if ($t.Trim() -eq '$env:COMPUTERNAME') { return $env:COMPUTERNAME }
                if ($t -match 'CCM_SoftwareUpdate' -and $t -match 'InstallUpdates') { return (& $ScriptBlock @ArgumentList) }
                return $null
            }
            try {
                [string](& $script:AcasKbInstallBlock -Computer $env:COMPUTERNAME -Cred $null -Auth 'Negotiate' -KBs @('KB5031234') -MsuPath '' -NoReboot $true -Method 'mecm')
            } finally {
                Remove-Item function:script:New-PSSession, function:script:Remove-PSSession, function:script:Get-WmiObject, function:script:Invoke-WmiMethod, function:script:Invoke-Command -EA SilentlyContinue
            }
        } $Rv
    }

    Context 'WPT kb-install (WptKbInstallBlock)' {
        It 'ReturnValue 0 => the KB is counted as installed (happy path unchanged)' {
            $r = Invoke-WptKb -Rv 0
            $r.MECMFound     | Should Be 1
            $r.MECMInstalled | Should Be 1
            $r.Errors        | Should BeNullOrEmpty
        }
        It 'NON-ZERO ReturnValue => NOT counted as installed, the rejection is reported' {
            $r = Invoke-WptKb -Rv 5
            $r.MECMInstalled | Should Be 0
            $r.MECMFound     | Should Be 1
            $r.Errors        | Should Match 'rejected'
            $r.Errors        | Should Match 'ReturnValue=5'
        }
        It 'NULL ReturnValue => NOT counted as installed (loop22 fail-closed), reported as <null>' {
            # -Rv -1 makes the shim return a method result WITHOUT a ReturnValue member,
            # so .ReturnValue is $null - a method that returned nothing must not read as success.
            $r = Invoke-WptKb -Rv -1
            $r.MECMInstalled | Should Be 0
            $r.MECMFound     | Should Be 1
            $r.Errors        | Should Match 'rejected'
            $r.Errors        | Should Match ([regex]::Escape('ReturnValue=<null>'))
        }
    }

    Context 'ACAS kb-install (AcasKbInstallBlock)' {
        It 'ReturnValue 0 => <<MECM=1>> and UNCONFIRMED (loop25: a trigger is not a confirmed install)' {
            # loop25: an accepted MECM InstallUpdates trigger is NOT a confirmed install (the async
            # install can fail later), so the honest status is UNCONFIRMED, not OK - it must stay out
            # of the OK/patched tally. This assertion previously (wrongly) pinned '^OK'.
            $s = Invoke-AcasKb -Rv 0
            $s | Should Match '<<MECM=1>>'
            $s | Should Match '^UNCONFIRMED'
        }
        It 'NON-ZERO ReturnValue => <<MECM=0>>, FAIL, and the rejection is reported' {
            $s = Invoke-AcasKb -Rv 5
            $s | Should Match '<<MECM=0>>'
            $s | Should Match '^FAIL'
            $s | Should Match 'rejected'
            $s | Should Match 'ReturnValue=5'
        }
    }
}

# -----------------------------------------------------------------------------
Describe 'FIX 2 - WinUpgrade Pin/Unpin gate success on a policy read-back (JanetWeb.winupgrade.psm1)' {

    $m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.winupgrade.psm1') -Force -PassThru

    # Drive the REAL worker with Invoke-Command shadowed. The write/removal call returns
    # a canned string; the read-back call (marker PINREAD) returns a canned policy state
    # so the worker's real verify+gate logic runs. Target = this box (reachable, fast).
    function Invoke-PinWorker {
        param($ReadBack)
        & $m {
            param($ReadBack)
            $script:__rb = $ReadBack
            function script:Invoke-Command {
                [CmdletBinding()] param($ComputerName,$ScriptBlock,$ArgumentList,$Authentication,$SessionOption,$Credential,$Session)
                $t = [string]$ScriptBlock
                if ($t -match 'PINREAD') { return $script:__rb }
                return 'ProductVersion=Windows 11; TargetReleaseVersionInfo=24H2'
            }
            try {
                $argl = @(
                    $env:COMPUTERNAME,'Pin',$null,'Windows 11','24H2',
                    '','',$false,$false,$true,
                    $false,$false,16384,$null,$null,
                    $false,$false,$false,$false,
                    'x',4,64,'2.0','y',
                    $false,300,$script:WinUpgradePinBlock
                )
                $row = & $script:WinUpgradeWorker @argl
                [pscustomobject]@{ Status=[string]$row.Status; Ok=[bool]$row.Ok; Detail=[string]$row.Detail }
            } finally { Remove-Item function:script:Invoke-Command -EA SilentlyContinue }
        } $ReadBack
    }

    function Invoke-UnpinWorker {
        param($ReadBack)
        & $m {
            param($ReadBack)
            $script:__rb = $ReadBack
            function script:Invoke-Command {
                [CmdletBinding()] param($ComputerName,$ScriptBlock,$ArgumentList,$Authentication,$SessionOption,$Credential,$Session)
                $t = [string]$ScriptBlock
                if ($t -match 'PINREAD') { return $script:__rb }
                return 'removal attempted; other policy values kept'
            }
            try {
                $argl = @(
                    $env:COMPUTERNAME,'Unpin',$null,'Windows 11','24H2',
                    '','',$false,$false,$true,
                    $false,$false,16384,$null,$null,
                    $false,$false,$false,$false,
                    'x',4,64,'2.0','y',
                    $false,300,$script:WinUpgradePinBlock
                )
                $row = & $script:WinUpgradeWorker @argl
                [pscustomobject]@{ Status=[string]$row.Status; Ok=[bool]$row.Ok; Detail=[string]$row.Detail }
            } finally { Remove-Item function:script:Invoke-Command -EA SilentlyContinue }
        } $ReadBack
    }

    Context 'Pin' {
        It 'read-back MATCHES the intended pin => DONE (happy path)' {
            $r = Invoke-PinWorker -ReadBack ([pscustomobject]@{ TargetReleaseVersion=1; ProductVersion='Windows 11'; TargetReleaseVersionInfo='24H2' })
            $r.Status | Should Be 'DONE'
            $r.Ok     | Should Be $true
        }
        It 'read-back MISMATCHES (e.g. GPO re-overwrote it) => NOT DONE' {
            $r = Invoke-PinWorker -ReadBack ([pscustomobject]@{ TargetReleaseVersion=1; ProductVersion='Windows 11'; TargetReleaseVersionInfo='23H2' })
            $r.Status | Should Be 'FAILED'
            $r.Ok     | Should Be $false
            $r.Detail | Should Match 'NOT VERIFIED'
        }
        It 'policy key not readable after write => NOT DONE (fail-closed)' {
            $r = Invoke-PinWorker -ReadBack $null
            $r.Status | Should Be 'FAILED'
            $r.Ok     | Should Be $false
        }
    }

    Context 'Unpin' {
        It 'read-back shows all three pin values GONE => removed (DONE)' {
            $r = Invoke-UnpinWorker -ReadBack ([pscustomobject]@{ KeyPresent=$false; HasTRV=$false; HasProduct=$false; HasInfo=$false })
            $r.Status | Should Be 'DONE'
            $r.Ok     | Should Be $true
        }
        It 'read-back shows a pin value STILL present => NOT reported removed' {
            $r = Invoke-UnpinWorker -ReadBack ([pscustomobject]@{ KeyPresent=$true; HasTRV=$true; HasProduct=$false; HasInfo=$false })
            $r.Status | Should Be 'FAILED'
            $r.Ok     | Should Be $false
            $r.Detail | Should Match 'NOT REMOVED'
            $r.Detail | Should Match 'TargetReleaseVersion'
        }
    }
}

# -----------------------------------------------------------------------------
Describe 'FIX 3 - Secure Boot Lenovo gates success on the post-write read-back (JanetWeb.secureboot.psm1)' {

    $sbm = Import-Module (Join-Path $script:Root 'modules\JanetWeb.secureboot.psm1') -Force -PassThru

    # The Lenovo enable logic lives in the remote payload here-string. Extract just the
    # New-Result + Enable-LenovoSecureBoot function definitions via the PS parser and run
    # them against a shimmed Get-WmiObject so the REAL post-write comparison executes.
    $payload = & $sbm { $script:SbePayload }
    $tk = $null; $er = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($payload, [ref]$tk, [ref]$er)
    $defs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and ($n.Name -eq 'New-Result' -or $n.Name -eq 'Enable-LenovoSecureBoot') }, $true)
    $script:__lenovoSrc = ($defs | ForEach-Object { $_.Extent.Text }) -join "`n`n"

    function Invoke-Lenovo {
        param([string]$PostValue, [string]$SetRet = 'Success', [string]$SaveRet = 'Success')
        & {
            param($src, $PostValue, $SetRet, $SaveRet)
            $BIOSPassword = 'pw'
            $script:__cnt = 0
            $script:__cur = 'SecureBoot,Disable'
            $script:__post = "SecureBoot,$PostValue"
            $script:__setret = $SetRet
            $script:__saveret = $SaveRet
            function Get-WmiObject {
                [CmdletBinding()] param($Class, $Namespace)
                switch ("$Class") {
                    'Lenovo_BiosSetting' {
                        $script:__cnt++
                        $val = if ($script:__cnt -le 1) { $script:__cur } else { $script:__post }
                        return ([pscustomobject]@{ CurrentSetting = $val })
                    }
                    'Lenovo_SetBiosSetting' {
                        $o = [pscustomobject]@{}
                        $o | Add-Member -MemberType ScriptMethod -Name SetBiosSetting -Value { param($a) [pscustomobject]@{ return = $script:__setret } }
                        return $o
                    }
                    'Lenovo_SaveBiosSettings' {
                        $o = [pscustomobject]@{}
                        $o | Add-Member -MemberType ScriptMethod -Name SaveBiosSettings -Value { param($a) [pscustomobject]@{ return = $script:__saveret } }
                        return $o
                    }
                }
            }
            Invoke-Expression $src
            $res = Enable-LenovoSecureBoot
            [pscustomobject]@{ NewValue = [string]$res.NewValue; Error = [string]$res.Error; SetResult = [string]$res.SetResult }
        } $script:__lenovoSrc $PostValue $SetRet $SaveRet
    }

    It 'post-write read-back == intended (Enabled) => clean success (no pending marker, no error)' {
        $r = Invoke-Lenovo -PostValue 'Enable'
        $r.Error    | Should BeNullOrEmpty
        $r.NewValue | Should Match 'Enable'
        $r.NewValue | Should Not Match 'pending'
    }
    It 'WMI returned Success but read-back != intended => flagged pending reboot (NOT a clean immediate success)' {
        $r = Invoke-Lenovo -PostValue 'Disable'
        $r.NewValue | Should Match 'pending reboot'
    }
    It 'WMI write refused (SetBiosSetting != Success) => Error set (failure)' {
        $r = Invoke-Lenovo -PostValue 'Enable' -SetRet 'Access Denied'
        $r.Error | Should Match 'BIOS write failed'
    }
}
