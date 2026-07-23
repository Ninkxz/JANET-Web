# =============================================================================
#  FixVerify.Tests.ps1 - Pester 3.4 tests for the three "reports success without
#  verifying" fixes. Each proves that VERIFICATION GATES SUCCESS and that a read
#  error FAILS CLOSED (never treated as empty/removed/restored).
#
#    FIX 1  DHCP  - option-read errors no longer collapse to "empty" (which would
#                   let Append wipe the live list / Remove short-circuit-wipe).
#    FIX 2  WPT   - maintenance lock/unlock report Locked/Restored only when the
#                   secedit read-back confirms the intended state.
#    FIX 3  UPR   - uninstall reports OK only when a post-uninstall re-enumeration
#                   confirms the product is actually gone.
#
#  All cmdlets that would leave this box (DhcpServer cmdlets / Invoke-Command /
#  New-PSSession) are shadowed IN MODULE SCOPE. No live host is touched.
#
#  Run:  Invoke-Pester -Path .\tests\FixVerify.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent

# -----------------------------------------------------------------------------
Describe 'FIX 1 - DHCP option reads fail-closed (JanetWeb.dhcp.psm1)' {

    $dm = Import-Module (Join-Path $script:Root 'modules\JanetWeb.dhcp.psm1') -Force -PassThru

    function Invoke-DhcpBulk {
        param([string]$ReadMode, [string]$Mode = 'Append')
        & $dm {
            param($ReadMode, $Mode)
            $script:__set = $false; $script:__remove = $false
            $script:__readmode = $ReadMode; $script:__getcalls = 0
            function script:Import-Module { param([Parameter(ValueFromRemainingArguments = $true)]$r) }
            function script:Get-DhcpServerv4OptionValue {
                param($ScopeId, $OptionId, $ErrorAction)
                $script:__getcalls++
                switch ($script:__readmode) {
                    'rpc'        { throw 'The RPC server is unavailable.' }
                    'notpresent' { throw 'The specified option value does not exist.' }
                    'staleerr'   { if ($script:__getcalls -ge 2) { throw 'The RPC server is unavailable.' } ; [pscustomobject]@{ Value = @('9.9.9.9') } }
                    default      { [pscustomobject]@{ Value = @('9.9.9.9') } }
                }
            }
            function script:Set-DhcpServerv4OptionValue { param($ScopeId, $OptionId, $Value, [switch]$Force, $ErrorAction) $script:__set = $true }
            function script:Remove-DhcpServerv4OptionValue { param($ScopeId, $OptionId, $ErrorAction) $script:__remove = $true }
            try {
                $res = & $script:DhcpBulkScript @('10.0.0.0') 6 @('1.2.3.4') $Mode $false
                $rec = @($res)[0]
                [pscustomobject]@{ Status = [string]$rec.Status; Error = [string]$rec.Error; Set = [bool]$script:__set; Remove = [bool]$script:__remove }
            } finally {
                Remove-Item function:script:Get-DhcpServerv4OptionValue, function:script:Set-DhcpServerv4OptionValue, function:script:Remove-DhcpServerv4OptionValue, function:script:Import-Module -EA SilentlyContinue
            }
        } $ReadMode $Mode
    }

    function Invoke-DhcpLoad {
        param([string]$ReadMode)
        & $dm {
            param($ReadMode)
            $script:__readmode = $ReadMode
            function script:Import-Module { param([Parameter(ValueFromRemainingArguments = $true)]$r) }
            function script:Get-DhcpServerv4OptionValue {
                param($ScopeId, $OptionId, $ErrorAction)
                switch ($script:__readmode) {
                    'rpc'        { throw 'The RPC server is unavailable.' }
                    'notpresent' { throw 'The specified option value does not exist.' }
                    default      { [pscustomobject]@{ Value = @('9.9.9.9') } }
                }
            }
            try {
                $r = & $script:DhcpLoadScript '10.0.0.0' 6
                [pscustomobject]@{ Ok = [bool]$r.Ok; NotSet = [bool]$r.NotSet; Values = @($r.Values); Err = [string]$r.Err }
            } finally {
                Remove-Item function:script:Get-DhcpServerv4OptionValue, function:script:Import-Module -EA SilentlyContinue
            }
        } $ReadMode
    }

    Context 'bulk apply (DhcpBulkScript)' {
        It 'READ ERROR on the initial read => ReadError and NO write (Append does not wipe the live list)' {
            $r = Invoke-DhcpBulk -ReadMode 'rpc' -Mode 'Append'
            $r.Status | Should Be 'ReadError'
            $r.Set    | Should Be $false
            $r.Remove | Should Be $false
            $r.Error  | Should Match 'fail-closed'
        }
        It 'READ ERROR on a Remove => ReadError and NO Remove (staleness short-circuit cannot wipe config)' {
            $r = Invoke-DhcpBulk -ReadMode 'rpc' -Mode 'Remove'
            $r.Status | Should Be 'ReadError'
            $r.Remove | Should Be $false
        }
        It 'READ ERROR on the pre-write RE-READ => ReadError and NO write' {
            $r = Invoke-DhcpBulk -ReadMode 'staleerr' -Mode 'Append'
            $r.Status | Should Be 'ReadError'
            $r.Set    | Should Be $false
        }
        It 'normal read => write proceeds as before (Changed, Set called)' {
            $r = Invoke-DhcpBulk -ReadMode 'normal' -Mode 'Append'
            $r.Status | Should Be 'Changed'
            $r.Set    | Should Be $true
        }
        It 'genuine "option not configured" is NOT a read error => Append still writes the new value' {
            $r = Invoke-DhcpBulk -ReadMode 'notpresent' -Mode 'Append'
            $r.Status | Should Be 'Changed'
            $r.Set    | Should Be $true
        }
    }

    Context 'load (DhcpLoadScript)' {
        It 'READ ERROR => Ok=$false (not a fake NotSet)' {
            $r = Invoke-DhcpLoad -ReadMode 'rpc'
            $r.Ok     | Should Be $false
            $r.NotSet | Should Be $false
            $r.Err    | Should Match 'read failed'
        }
        It 'genuine "does not exist" => Ok=$true, NotSet=$true' {
            $r = Invoke-DhcpLoad -ReadMode 'notpresent'
            $r.Ok     | Should Be $true
            $r.NotSet | Should Be $true
        }
        It 'normal read => Ok=$true with the value' {
            $r = Invoke-DhcpLoad -ReadMode 'normal'
            $r.Ok     | Should Be $true
            $r.NotSet | Should Be $false
            ($r.Values -contains '9.9.9.9') | Should Be $true
        }
    }
}

# -----------------------------------------------------------------------------
Describe 'FIX 2 - WPT maintenance lock/unlock gate success on secedit read-back (JanetWeb.wpt.psm1)' {

    $wm = Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Force -PassThru

    function Invoke-WptLock {
        param($LockResult)
        & $wm {
            param($LockResult)
            function script:Invoke-Command {
                param($ComputerName, $ScriptBlock, $ArgumentList, $ErrorAction, $Credential, $Authentication, $SessionOption)
                if ($ScriptBlock -and ($ScriptBlock.ToString().Trim() -eq '$env:COMPUTERNAME')) { return $env:COMPUTERNAME }
                return $LockResult
            }
            try {
                $out = & $script:WptMaintLockBlock -Computer $env:COMPUTERNAME -Cred $null -Auth 'Default' -Caption 'C' -Message 'M' -HardLock $true
                [pscustomobject]@{ Success = [bool]$out.Success; Mode = [string]$out.Mode; Detail = [string]$out.Detail }
            } finally { Remove-Item function:script:Invoke-Command -EA SilentlyContinue }
        } $LockResult
    }

    function Invoke-WptUnlock {
        param($UnlockResult)
        & $wm {
            param($UnlockResult)
            function script:Invoke-Command {
                param($ComputerName, $ScriptBlock, $ArgumentList, $ErrorAction, $Credential, $Authentication, $SessionOption)
                return $UnlockResult
            }
            try {
                $out = & $script:WptMaintUnlockBlock -Computer $env:COMPUTERNAME -Cred $null -Auth 'Default'
                [pscustomobject]@{ Success = [bool]$out.Success; Detail = [string]$out.Detail }
            } finally { Remove-Item function:script:Invoke-Command -EA SilentlyContinue }
        } $UnlockResult
    }

    It 'LOCK: read-back confirms the intended state => Success (HOST LOCKED)' {
        $r = Invoke-WptLock -LockResult @{ Banner = $true; HardLock = $true; Err = '' }
        $r.Success | Should Be $true
        $r.Mode    | Should Be 'Hard lock'
    }
    It 'LOCK: read-back does NOT match (unverified) => NOT reported locked' {
        $r = Invoke-WptLock -LockResult @{ Banner = $true; HardLock = $false; Err = 'hardlock NOT verified (secedit exit=0; effective SeInteractiveLogonRight=; users may NOT be locked)' }
        $r.Success | Should Be $false
        $r.Mode    | Should Be 'Failed'
        $r.Detail  | Should Match 'NOT verified'
    }
    It 'UNLOCK: read-back confirms restore => Success' {
        $r = Invoke-WptUnlock -UnlockResult @{ Banner = $true; Restored = $true; Source = 'backup'; Err = '' }
        $r.Success | Should Be $true
    }
    It 'UNLOCK: read-back does NOT match (unverified) => NOT reported restored (users may still be locked out)' {
        $r = Invoke-WptUnlock -UnlockResult @{ Banner = $true; Restored = $false; Source = 'backup'; Err = 'restore NOT verified -- users may still be locked out (secedit exit=0)' }
        $r.Success | Should Be $false
        $r.Detail  | Should Match 'NOT verified'
    }
}

# -----------------------------------------------------------------------------
Describe 'FIX 3 - UPR uninstall gates OK on a post-uninstall re-enumeration (JanetWeb.upr.psm1)' {

    $um = Import-Module (Join-Path $script:Root 'modules\JanetWeb.upr.psm1') -Force -PassThru

    function Invoke-UprVerify {
        param([bool]$Present, [string]$UninstallResult, [switch]$VerifyThrows)
        & $um {
            param($Present, $UninstallResult, $VerifyThrows)
            $script:__present = $Present
            $script:__uninstallResult = $UninstallResult
            $script:__verifyThrows = [bool]$VerifyThrows
            function script:New-PSSession { param($ComputerName, $SessionOption, $Authentication, $ErrorAction, $Credential) return ([pscustomobject]@{ Id = 1; Name = 'shim' }) }
            function script:Remove-PSSession { param($Session, $ErrorAction) }
            function script:Invoke-Command {
                param($Session, $ComputerName, $ScriptBlock, $ArgumentList, $ErrorAction, $Credential, $Authentication, $SessionOption)
                if ($ScriptBlock -and ($ScriptBlock.ToString() -match 'UprVerifyPresent')) {
                    if ($script:__verifyThrows) { throw 'winrm re-read failed' }
                    return ([pscustomobject]@{ Present = $script:__present })
                }
                if ($ArgumentList) { return $script:__uninstallResult }
                # audit 2026-07-23: harness updated for the folded guard - the standalone DNS
                # probe is gone; the enumeration now ALSO returns the answering box's
                # ComputerName (this box, so the admin-side compare passes and the verify
                # gating under test is reached). Apps carries what the old shim returned.
                # Assertions unchanged.
                return @{ ComputerName = $env:COMPUTERNAME; Apps = @( @{ Name = 'FakeVulnApp'; Version = '1.0'; Publisher = 'x'; Type = 'EXE'; UninstallString = 'C:\x.exe'; QuietUninstall = ''; PSChildName = 'FakeVulnApp' } ) }
            }
            try {
                $prof = @{ DisplayNameRegex = 'FakeVulnApp'; VersionMaxExclusive = ''; Proven = $true; PluginNameMatch = 'P'; Notes = 'n' }
                $out = & $script:UprWorkerBlock -ConnectTarget $env:COMPUTERNAME -Profiles @($prof) -Cred $null -Auth 'Negotiate' -DoUninstall $true -DryRun $false -RemoveSet $null
                $cand = @($out.Candidates)[0]
                [pscustomobject]@{ Error = [string]$out.Error; CandResult = [string]$cand.Result }
            } finally { Remove-Item function:script:Invoke-Command, function:script:New-PSSession, function:script:Remove-PSSession -EA SilentlyContinue }
        } $Present $UninstallResult $VerifyThrows
    }

    It 'success exit but product STILL PRESENT after re-enum => FAILURE (not OK)' {
        $r = Invoke-UprVerify -Present $true -UninstallResult 'OK (EXE exit 0)'
        $r.CandResult | Should Match 'still present'
        $r.CandResult | Should Match '^FAIL'
    }
    It 'success exit and product ABSENT after re-enum => OK (removal verified)' {
        $r = Invoke-UprVerify -Present $false -UninstallResult 'OK (EXE exit 0)'
        $r.CandResult | Should Be 'OK (EXE exit 0)'
    }
    It '3010 exit and product ABSENT => "removed, reboot required" (not claimed fully clean)' {
        $r = Invoke-UprVerify -Present $false -UninstallResult 'OK (EXE exit 3010)'
        $r.CandResult | Should Match 'reboot required'
    }
    It 'post-uninstall re-read UNREADABLE => fail-closed FAILURE (does not claim removed)' {
        $r = Invoke-UprVerify -Present $false -UninstallResult 'OK (EXE exit 0)' -VerifyThrows
        $r.CandResult | Should Match 'could NOT be verified'
        $r.CandResult | Should Match '^FAIL'
    }
}
