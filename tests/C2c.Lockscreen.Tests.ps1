# =============================================================================
#  C2c.Lockscreen.Tests.ps1 - Pester 3.4 for the v1.9.0 Lock Screen / Wallpaper
#  Cache fix (fix-lockscreen). Drives the DESTRUCTIVE fix worker's Lockscreen
#  branch LOCALLY: New-PSSession / Remove-PSSession / Invoke-Command and the
#  registry / filesystem cmdlets are shadowed in MODULE scope, so the registry
#  logic runs against fakes - no real WinRM, no real HKLM write.
#
#  Run:  Invoke-Pester -Path .\tests\C2c.Lockscreen.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$cm = Import-Module (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1') -Force -PassThru

# Drive the fix worker's Lockscreen branch LOCALLY.
#   -Cur      : hashtable of values ALREADY present under the Personalization policy key
#   -HasPkgLock / -HasDefLock / -HasDefDesk : which default image files "exist" on the target
function Invoke-C2cFixLockscreen {
    param([hashtable]$Cur = @{}, [bool]$HasPkgLock = $false, [bool]$HasDefLock = $true, [bool]$HasDefDesk = $true)
    & $cm {
        param($Cur, $HasPkgLock, $HasDefLock, $HasDefDesk)
        $script:__cur    = $Cur
        $script:__writes = New-Object System.Collections.ArrayList
        $pkgLock = "$env:ProgramData\Microsoft\User Account Pictures\LockScreen.jpg"
        $defLock = "$env:SystemRoot\Web\Screen\img100.jpg"
        $defDesk = "$env:SystemRoot\Web\Wallpaper\Windows\img0.jpg"
        $script:__images = New-Object System.Collections.Generic.HashSet[string]
        if ($HasPkgLock) { [void]$script:__images.Add($pkgLock) }
        if ($HasDefLock) { [void]$script:__images.Add($defLock) }
        if ($HasDefDesk) { [void]$script:__images.Add($defDesk) }

        function script:New-PSSession { param($ComputerName, $SessionOption, $Authentication, $ErrorAction, $Credential) [pscustomobject]@{ Id = 1; Name = 'shim' } }
        function script:Remove-PSSession { param($Session, $ErrorAction) }
        function script:Invoke-Command {
            param($Session, $ComputerName, $ScriptBlock, $ArgumentList, $ErrorAction, $Credential, $Authentication, $SessionOption)
            if ($ScriptBlock -and ($ScriptBlock.ToString().Trim() -eq '$env:COMPUTERNAME')) { return $env:COMPUTERNAME }
            return (& $ScriptBlock @ArgumentList)
        }
        function script:Test-Path {
            param($LiteralPath, $Path, $ErrorAction)
            $p = if ($LiteralPath) { [string]$LiteralPath } else { [string]$Path }
            if ($p -match 'Policies\\Microsoft\\Windows\\Personalization$') { return $true }   # key exists
            return $script:__images.Contains($p)
        }
        function script:New-Item { param($Path, [switch]$Force, $ErrorAction) $null }
        function script:Get-ItemProperty {
            param($LiteralPath, $Path, $Name, $ErrorAction)
            $o = New-Object pscustomobject
            foreach ($k in $script:__cur.Keys) { $o | Add-Member -NotePropertyName $k -NotePropertyValue $script:__cur[$k] }
            return $o
        }
        function script:New-ItemProperty {
            param($LiteralPath, $Path, $Name, $Value, $PropertyType, [switch]$Force, $ErrorAction)
            [void]$script:__writes.Add([pscustomobject]@{ Name = [string]$Name; Value = [string]$Value; Type = [string]$PropertyType })
            $null
        }
        function script:Get-ChildItem { param($LiteralPath, $Path, $Filter, $ErrorAction) @() }
        try {
            $res = & $script:C2cFixBlock $env:COMPUTERNAME $null 'Default' $true @('Lockscreen') $false 'Tanium Client' $script:C2cTaniumInstalledSrc
            $ls = @(@($res.Pillars) | Where-Object { $_.Name -eq 'Lockscreen' })[0]
            [pscustomobject]@{
                HostStatus = [string]$res.Status
                Result     = $(if ($ls) { [string]$ls.Result } else { '' })
                Detail     = $(if ($ls) { [string]$ls.Detail } else { '' })
                Writes     = @($script:__writes)
            }
        } finally {
            Remove-Item function:script:New-PSSession, function:script:Remove-PSSession, function:script:Invoke-Command, `
                function:script:Test-Path, function:script:New-Item, function:script:Get-ItemProperty, `
                function:script:New-ItemProperty, function:script:Get-ChildItem -ErrorAction SilentlyContinue
        }
    } $Cur $HasPkgLock $HasDefLock $HasDefDesk
}

Describe 'C2C v1.9.0 - fix-lockscreen writes the Personalization policy only when unset' {

    It 'no existing values + default images present -> FIXED, sets LockScreenImage + the 3 Desktop values' {
        $r = Invoke-C2cFixLockscreen -Cur @{} -HasDefLock $true -HasDefDesk $true
        $r.Result | Should Be 'FIXED'
        $names = @($r.Writes | ForEach-Object { $_.Name })
        $names -contains 'LockScreenImage'   | Should Be $true
        $names -contains 'DesktopImagePath'  | Should Be $true
        $names -contains 'DesktopImageUrl'   | Should Be $true
        $names -contains 'DesktopImageStatus'| Should Be $true
    }
    It 'LockScreenImage already set (desktop unset) -> only the desktop values are written, lock is left alone' {
        $r = Invoke-C2cFixLockscreen -Cur @{ LockScreenImage = 'C:\existing\lock.jpg' }
        $r.Result | Should Be 'FIXED'
        $names = @($r.Writes | ForEach-Object { $_.Name })
        $names -contains 'LockScreenImage'  | Should Be $false     # NEVER overwritten
        $names -contains 'DesktopImagePath' | Should Be $true
        $r.Detail | Should Match '(?i)lock already set'
    }
    It 'both already set -> NO CHANGE, writes nothing' {
        $r = Invoke-C2cFixLockscreen -Cur @{ LockScreenImage = 'a'; DesktopImagePath = 'b' }
        $r.Result | Should Be 'NOCHANGE'
        @($r.Writes).Count | Should Be 0
    }
    It 'no default image found on the target -> SKIP, writes nothing' {
        $r = Invoke-C2cFixLockscreen -Cur @{} -HasPkgLock $false -HasDefLock $false -HasDefDesk $false
        $r.Result | Should Be 'SKIP'
        @($r.Writes).Count | Should Be 0
    }
    It 'prefers the unquarantine package LockScreen.jpg when it is present' {
        $r = Invoke-C2cFixLockscreen -Cur @{} -HasPkgLock $true -HasDefLock $true -HasDefDesk $false
        $lock = @($r.Writes | Where-Object { $_.Name -eq 'LockScreenImage' })[0]
        $lock.Value | Should Match '(?i)User Account Pictures\\LockScreen\.jpg'
    }
    It 'DesktopImageStatus is written as a DWORD value 1' {
        $r = Invoke-C2cFixLockscreen -Cur @{}
        $st = @($r.Writes | Where-Object { $_.Name -eq 'DesktopImageStatus' })[0]
        $st.Type  | Should Be 'DWord'
        $st.Value | Should Be '1'
    }
}

Describe 'C2C v1.9.0 - fix-lockscreen is wired as an opt-in action, NOT a run-all pillar' {
    It 'the manifest exposes fix-lockscreen (destructive, needs FIX confirm)' {
        $man = & $cm { Get-JanetToolManifest }
        $a = @($man.actions | Where-Object { $_.id -eq 'fix-lockscreen' })[0]
        $a | Should Not BeNullOrEmpty
        $a.destructive | Should Be $true
        @($a.inputs | Where-Object { $_.name -eq 'confirm' }).Count | Should Be 1
    }
    It 'Lockscreen is NOT an endpoint-fixable (run-all) pillar' {
        & $cm { $script:C2cFixablePillars -contains 'Lockscreen' } | Should Be $false
    }
    It 'fix-lockscreen maps to the Lockscreen pillar' {
        & $cm { $script:C2cPillarByAction['fix-lockscreen'] } | Should Be 'Lockscreen'
    }
    It 'reports tool version 1.10.0' {
        (& $cm { Get-JanetToolManifest }).version | Should Be '1.10.0'
    }
}
