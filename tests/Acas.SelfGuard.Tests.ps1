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
