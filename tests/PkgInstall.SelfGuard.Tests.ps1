# =============================================================================
#  PkgInstall.SelfGuard.Tests.ps1 - Pester 3.4 for the loop-10 pkginstall
#  dispatcher self-guard (v2.5.8). The loop-10 self-guard-coverage audit found
#  pkginstall's deploy-psadt / deploy-msi-bundle were destructive fleet fan-outs
#  with NO self-guard infrastructure at all (only a wrong-box compare, which does
#  NOT protect the dispatcher: self is dialed by its own correct name -> no
#  COMPUTERNAME mismatch). Installing a package (PSADT Deploy-Application.ps1 /
#  msiexec /i) on the JANET host is never intended and can reboot it. Both deploy
#  actions now drop the dispatcher BEFORE fan-out (unconditional - no dry-run).
#
#  These tests drive the real Invoke-JanetToolAction with a self-only target; the
#  self-guard short-circuits to total=0 with a Self-guard warn BEFORE the runspace
#  pool, so NO WinRM / New-PSDrive / package copy ever leaves the box.
#
#  Run:  Invoke-Pester -Path .\tests\PkgInstall.SelfGuard.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.pkginstall.psm1') -Force -PassThru

function Invoke-Pkg([string]$aid, [hashtable]$p) {
    $evs = New-Object System.Collections.ArrayList
    $emit = { param($e) [void]$evs.Add($e) }
    $res = & $m { param($a,$pp,$em) Invoke-JanetToolAction -ActionId $a -Params $pp -Credential $null -Emit $em } $aid $p $emit
    @{ Result = $res; Events = @($evs) }
}
function Has-SelfGuardWarn($o) {
    @($o.Events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and $_.text -match 'Self-guard' }).Count -gt 0
}
$script:Me = $env:COMPUTERNAME

Describe 'pkginstall manifest (self-guard floor)' {
    $mani = & $m { Get-JanetToolManifest }
    It 'manifest id is pkginstall and version is at least 2.5.8' {
        # Floor: the newest bump's own file holds the exact pin (loop60 = Pkginstall.MsiList, v2.5.9).
        [string]$mani.id      | Should Be 'pkginstall'
        ([version][string]$mani.version -ge [version]'2.5.8') | Should Be $true
    }
    It 'both deploy actions are destructive' {
        foreach ($aid in @('deploy-psadt','deploy-msi-bundle')) {
            $a = @($mani.actions | Where-Object { $_.id -eq $aid })[0]
            [bool]$a.destructive | Should Be $true
        }
    }
}

Describe 'pkginstall self-guard predicate (Test-PkgInstallHostIsSelf)' {
    It 'flags loopback + this dispatcher shortname as self' {
        (& $m { Test-PkgInstallHostIsSelf '127.0.0.1' }) | Should Be $true
        (& $m { param($h) Test-PkgInstallHostIsSelf $h } $script:Me) | Should Be $true
    }
    It 'does NOT flag an obviously-remote host (no over-drop)' {
        (& $m { Test-PkgInstallHostIsSelf 'WS-REMOTE-321' }) | Should Be $false
    }
    It 'the identity set contains every actually-bound local IPv4 (DNS-miss-proof)' {
        $ident = & $m { Get-PkgInstallLocalIdentity }
        $bound = New-Object System.Collections.ArrayList
        foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($nic.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up) { continue }
            foreach ($ua in $nic.GetIPProperties().UnicastAddresses) {
                if ($ua.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { [void]$bound.Add($ua.Address.IPAddressToString) }
            }
        }
        foreach ($ip in @($bound | Select-Object -Unique)) { $ident.Contains($ip) | Should Be $true }
    }
}

Describe 'pkginstall deploy self-guards the dispatcher BEFORE fan-out' {
    It 'deploy-psadt targeting only the dispatcher (loopback) is emptied, no fan-out' {
        $o = Invoke-Pkg 'deploy-psadt' @{ targets = '127.0.0.1' }
        [int]$o.Result.summary.total | Should Be 0
        (Has-SelfGuardWarn $o) | Should Be $true
    }
    It 'deploy-msi-bundle targeting only the dispatcher shortname is emptied, no fan-out' {
        $o = Invoke-Pkg 'deploy-msi-bundle' @{ targets = $script:Me }
        [int]$o.Result.summary.total | Should Be 0
        [int]$o.Result.summary.selfSkipped | Should Be 1
    }
    It 'a self target mixed with junk still empties to the self-guard (only self was valid)' {
        $o = Invoke-Pkg 'deploy-psadt' @{ targets = "127.0.0.1`n\\srv\c$" }
        [int]$o.Result.summary.total | Should Be 0
        (Has-SelfGuardWarn $o) | Should Be $true
    }
}
