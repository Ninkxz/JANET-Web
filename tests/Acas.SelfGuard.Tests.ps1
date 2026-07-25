# =============================================================================
#  Acas.SelfGuard.Tests.ps1 - Pester 3.4 for the ACAS Nemesis 1.11.1 dispatcher
#  self-guard hardening (P2 fix). PURE / offline unit scope - no real host, no
#  WinRM, no shutdown.exe, no MECM. We assert the destructive dispatch paths can
#  NEVER target the JANET box (the host running the HttpListener) itself:
#
#   (a) 'schedule-reboot' with a self-only target -> total=0, a Self-guard warn,
#       and NO 'Scheduling reboot on N host(s)' fan-out is ever started;
#   (b) 'kb-install'      with a self-only host   -> total=0, a Self-guard warn,
#       and NO 'KB install ... on N host(s)' work is ever started;
#   (c) Select-AcasNonSelfHosts now DROPS self for a NON-ForbidSelf profile
#       (regression lock for the 1.11.1 broadening - the drop is unconditional
#       across every destructive App-Update wave, not just Java-Remove).
#
#  Reuses the shim/dispatch idiom from tests\Acas.FixJava.Tests.ps1.
#
#  Run:  Invoke-Pester -Path .\tests\Acas.SelfGuard.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$mod = Import-Module (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Force -PassThru

$Self    = $env:COMPUTERNAME
$ScProfile = 'Oracle Java - Software Center'   # a registered NON-ForbidSelf profile

Describe 'ACAS 1.11.1 - schedule-reboot self-guard (never reboot the dispatcher)' {

    It 'a self-only reboot wave returns total=0 with a Self-guard warn and NO reboot job' {
        $evts = New-Object System.Collections.ArrayList
        $emit = { param($e) [void]$evts.Add($e) }
        $res = & $mod {
            param($aid, $prm, $em)
            Invoke-JanetToolAction -ActionId $aid -Params $prm -Credential $null -Emit $em
        } 'schedule-reboot' @{ targets = $Self } $emit

        [int]$res.summary.total | Should Be 0
        @($res.rows).Count      | Should Be 0
        # Self-guard warning fired...
        $warn = @($evts | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and $_.text -match 'Self-guard' -and $_.text -match 'reboot' })
        $warn.Count | Should BeGreaterThan 0
        # ...and NO reboot fan-out ('Scheduling reboot on N host(s)') ever started.
        $started = @($evts | Where-Object { $_.type -eq 'status' -and $_.text -match 'Scheduling reboot on \d+ host' })
        $started.Count | Should Be 0
    }

    It 'a loopback-only reboot wave (127.0.0.1) is also emptied by the self-guard' {
        $evts = New-Object System.Collections.ArrayList
        $emit = { param($e) [void]$evts.Add($e) }
        $res = & $mod {
            param($aid, $prm, $em)
            Invoke-JanetToolAction -ActionId $aid -Params $prm -Credential $null -Emit $em
        } 'schedule-reboot' @{ targets = '127.0.0.1' } $emit

        [int]$res.summary.total | Should Be 0
        $warn = @($evts | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and $_.text -match 'Self-guard' })
        $warn.Count | Should BeGreaterThan 0
    }
}

Describe 'ACAS 1.11.1 - kb-install self-guard (never service KB on the dispatcher)' {

    It 'a self-only KB wave returns total=0 with a Self-guard warn and NO install started' {
        $evts = New-Object System.Collections.ArrayList
        $emit = { param($e) [void]$evts.Add($e) }
        $res = & $mod {
            param($aid, $prm, $em)
            Invoke-JanetToolAction -ActionId $aid -Params $prm -Credential $null -Emit $em
        } 'kb-install' @{ pairs = "$Self | KB5000001"; method = 'mecm' } $emit

        [int]$res.summary.total | Should Be 0
        @($res.rows).Count      | Should Be 0
        $warn = @($evts | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and $_.text -match 'Self-guard' -and $_.text -match 'KB-install' })
        $warn.Count | Should BeGreaterThan 0
        # The 'KB install (mecm) on N host(s)' info log sits AFTER the self-guard, so
        # short-circuiting means it never fires.
        $started = @($evts | Where-Object { $_.type -eq 'log' -and $_.text -match 'KB install .* on \d+ host' })
        $started.Count | Should Be 0
    }
}

Describe 'ACAS 1.11.1 - Select-AcasNonSelfHosts broadening (unconditional self-drop)' {

    It 'drops self for a NON-ForbidSelf profile (was untouched pre-1.11.1)' {
        $out = & $mod {
            param($n, $me)
            @(Select-AcasNonSelfHosts -ProfileName $n -Hosts @($me, 'FAR-HOST-1') -Send { param($e) })
        } $ScProfile $Self
        @($out) -contains $Self        | Should Be $false   # dispatcher dropped now
        @($out) -contains 'FAR-HOST-1' | Should Be $true    # real target kept
        @($out).Count | Should Be 1
    }

    It 'a NON-ForbidSelf wave whose ONLY host is self is emptied' {
        $out = & $mod {
            param($n, $me)
            @(Select-AcasNonSelfHosts -ProfileName $n -Hosts @($me) -Send { param($e) })
        } $ScProfile $Self
        @($out).Count | Should Be 0
    }

    It 'emits a Self-guard warning naming the dropped dispatcher host' {
        $evts = New-Object System.Collections.ArrayList
        $emit = { param($e) [void]$evts.Add($e) }
        $null = & $mod {
            param($n, $me, $em)
            @(Select-AcasNonSelfHosts -ProfileName $n -Hosts @($me, 'FAR-HOST-1') -Send $em)
        } $ScProfile $Self $emit
        $warn = @($evts | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and $_.text -match 'Self-guard' })
        $warn.Count | Should BeGreaterThan 0
    }
}

# =============================================================================
#  audit 2026-07-24 (P4) - acas was the ONLY one of 13 identity sets WITHOUT the
#  bound-NIC IPv4 enumeration (block copied verbatim from restart.psm1). The DNS
#  lookup only returns addresses registered under this box's own name, so a
#  management / OOB NIC IP (or one whose DNS record is lagging) was NOT in the
#  identity set - a pasted IP literal for it slipped the self-guard and the
#  dispatcher could be sent a reboot / KB install / Java removal.
#
#  Deterministic without touching DNS: point $env:COMPUTERNAME at a name that
#  cannot resolve, so BOTH Dns branches throw and are swallowed. The only
#  remaining source of local IPv4s is the NIC enumeration this fix added.
# =============================================================================
Describe 'ACAS self-guard - bound-NIC IPv4 parity (audit 2026-07-24)' {

    $bound = @()
    foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if ($nic.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up) { continue }
        foreach ($ua in $nic.GetIPProperties().UnicastAddresses) {
            if ($ua.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { $bound += $ua.Address.IPAddressToString }
        }
    }
    $bound = @($bound | Select-Object -Unique)

    It 'this box has at least one bound unicast IPv4 (else the check below is vacuous)' {
        @($bound).Count | Should BeGreaterThan 0
    }

    It 'every bound unicast IPv4 is SELF even when DNS cannot resolve this box' {
        $realName = $env:COMPUTERNAME
        $hits = @()
        try {
            $env:COMPUTERNAME = 'JANET-NOSUCHHOST-ZQX9'
            $hits = & $mod {
                param($ips)
                $script:AcasLocalIdentity = $null       # drop the cached (DNS-built) set
                $out = New-Object System.Collections.ArrayList
                foreach ($ip in $ips) { if (Test-AcasHostIsSelf $ip) { [void]$out.Add($ip) } }
                ,@($out.ToArray())
            } $bound
        } finally {
            $env:COMPUTERNAME = $realName
            & $mod { $script:AcasLocalIdentity = $null }   # never leave the bogus set cached
        }
        @($hits).Count | Should Be @($bound).Count
    }

    It 'the identity set itself carries every bound unicast IPv4' {
        $realName = $env:COMPUTERNAME
        $missing = @()
        try {
            $env:COMPUTERNAME = 'JANET-NOSUCHHOST-ZQX9'
            $missing = & $mod {
                param($ips)
                $script:AcasLocalIdentity = $null
                $set = Get-AcasLocalIdentity
                ,@(@($ips) | Where-Object { -not $set.Contains($_) })
            } $bound
        } finally {
            $env:COMPUTERNAME = $realName
            & $mod { $script:AcasLocalIdentity = $null }
        }
        @($missing).Count | Should Be 0
    }
}
