# =============================================================================
#  BiosFirmware.Tests.ps1 - Pester 3.4 tests for JanetWeb.biosfirmware.psm1
#  (audit 2026-07-24). Two things are pinned here:
#
#    1. the DNS-mismatch guard's IPv4-literal carve-out - an IP-addressed target
#       must NOT be reported as skipped (it was, 100% of the time, before);
#    2. the BIOS version comparison - '1.9.0' vs '1.10.0' and Dell's 'A9' vs
#       'A12' both order backwards as text, so a string compare would call an
#       out-of-date box Current.
#
#  New-Object/New-PSSession/Invoke-Command/Remove-PSSession are shadowed inside
#  the module scope, so NO WinRM call and NO TCP connect ever leaves this box.
#
#  Run:  Invoke-Pester -Path .\tests\BiosFirmware.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.biosfirmware.psm1') -Force -PassThru

# Drive the real worker scriptblock with a faked-out network: the TCP probe always
# "connects", the session is a stub, and the single Invoke-Command round-trip
# returns whatever remote COMPUTERNAME / BIOS bundle the caller asked for.
function Invoke-FakeScan {
    param([string]$Computer, [string]$RemoteName)
    & $script:Mod {
        param($computer, $remoteName)
        function script:New-Object {
            param([Parameter(Position = 0)][string]$TypeName, [Parameter(Position = 1)]$ArgumentList)
            $wh = [pscustomobject]@{}
            $wh | Add-Member -MemberType ScriptMethod -Name WaitOne -Value { param($ms, $ctx) $true }
            $iar = [pscustomobject]@{ AsyncWaitHandle = $wh }
            $tc = [pscustomobject]@{ Connected = $true }
            $tc | Add-Member -MemberType ScriptMethod -Name BeginConnect -Value { param($c, $p, $cb, $st) $iar }.GetNewClosure()
            $tc | Add-Member -MemberType ScriptMethod -Name Close -Value { }
            return $tc
        }
        function script:New-PSSession {
            [CmdletBinding()] param($ComputerName, $SessionOption, $Credential, $Authentication, [switch]$UseSSL)
            [pscustomobject]@{ Id = 1; ComputerName = $ComputerName }
        }
        function script:Remove-PSSession { [CmdletBinding()] param([Parameter(Position = 0)]$Session) }
        function script:Invoke-Command {
            [CmdletBinding()] param($Session, [scriptblock]$ScriptBlock)
            @{ Name = $remoteName; Manufacturer = 'Dell Inc.'; Model = 'Latitude 5420'
               ProductName = 'Latitude 5420'; BiosVersion = '1.50.0'; BiosDate = '2026-01-05' }
        }
        try { & $script:BiosFirmwareScanBlock $computer $null 'Default' }
        finally {
            # audit 2026-07-25 (fable re-audit follow-up): 'function:script:<name>' does NOT
            # resolve (it is read as a function literally named 'script:<name>'), so with
            # -EA SilentlyContinue these shims silently SURVIVED the fake scan and the next
            # Describe's New-Object handed back the TcpClient stub. Unqualified path removes
            # the script-scoped function for real.
            foreach ($fn in 'New-Object','New-PSSession','Remove-PSSession','Invoke-Command') {
                Remove-Item -LiteralPath "function:$fn" -ErrorAction SilentlyContinue
            }
        }
    } $Computer $RemoteName
}

function Get-Status {
    param([string]$Installed, [string]$Target)
    & $script:Mod { param($i, $t) Get-BiosComplianceStatus -Installed $i -Target $t } $Installed $Target
}

Describe 'DNS-mismatch guard IPv4-literal carve-out (audit 2026-07-24)' {

    It 'does NOT skip an IPv4-literal target whose name differs from the address' {
        # '192.168.10.50' -split '.' -> '192', which can never equal a COMPUTERNAME:
        # before the carve-out this made EVERY IP-addressed host a false skip.
        $r = Invoke-FakeScan -Computer '192.168.10.50' -RemoteName 'WS-BRAVO'
        $r.Error | Should Not Match 'DNS mismatch'
        $r.Error | Should Be ''
        $r.InstalledBIOS | Should Be '1.50.0'
        $r.Model | Should Be 'Latitude 5420'
    }

    It 'still skips a HOSTNAME target when a different box answers' {
        $r = Invoke-FakeScan -Computer 'WS-ALPHA' -RemoteName 'WS-BRAVO'
        $r.Error | Should Match 'DNS mismatch'
        $r.Error | Should Match 'skipped'
        $r.InstalledBIOS | Should Be ''
    }

    It 'passes a hostname target when the right box answers (FQDN short-name compare)' {
        $r = Invoke-FakeScan -Computer 'ws-alpha.contoso.mil' -RemoteName 'WS-ALPHA'
        $r.Error | Should Be ''
        $r.InstalledBIOS | Should Be '1.50.0'
    }
}

Describe 'BIOS version comparison is not a string compare (audit 2026-07-24)' {

    It 'orders dotted 1.9.0 BELOW 1.10.0 (text ordering says the opposite)' {
        Get-Status -Installed '1.9.0'  -Target '1.10.0' | Should Be 'Outdated'
        Get-Status -Installed '1.10.0' -Target '1.9.0'  | Should Be 'Current'
    }

    It 'orders Dell-style A9 BELOW A12 (text ordering says the opposite)' {
        Get-Status -Installed 'A9'  -Target 'A12' | Should Be 'Outdated'
        Get-Status -Installed 'A12' -Target 'A9'  | Should Be 'Current'
    }

    It 'treats an equal version as Current in both formats' {
        Get-Status -Installed '1.50.0' -Target '1.50.0' | Should Be 'Current'
        Get-Status -Installed 'A12'    -Target 'A12'    | Should Be 'Current'
    }

    It 'bumps the Dell letter series ahead of the revision (B02 > A25)' {
        Get-Status -Installed 'B02' -Target 'A25' | Should Be 'Current'
        Get-Status -Installed 'A25' -Target 'B02' | Should Be 'Outdated'
    }

    It 'takes the TRAILING dotted token so a model number cannot pollute the major' {
        Get-Status -Installed 'N40 Ver. 01.28' -Target '1.28' | Should Be 'Current'
        Get-Status -Installed 'N40 Ver. 01.27' -Target '1.28' | Should Be 'Outdated'
    }

    It 'refuses to score two different vendor formats rather than guessing' {
        Get-Status -Installed 'A12' -Target '1.10.0' | Should Be 'Unknown (version format)'
    }

    It 'compares the Dell letter series ORDINALLY (audit 2026-07-25)' {
        # The parser upper-cases both series, so an ordinal compare is a strict superset of
        # the old culture-sensitive one for every shape this tool sees - and it cannot be
        # re-collated by whatever culture the service happens to be running as.
        Get-Status -Installed 'B02' -Target 'A25' | Should Be 'Current'
        Get-Status -Installed 'a25' -Target 'B02' | Should Be 'Outdated'
    }
}

Describe 'Unknown states stay distinguishable (audit 2026-07-24)' {

    It 'reports an unreadable BIOS version separately from a missing baseline' {
        Get-Status -Installed ''    -Target '1.50.0' | Should Be 'Unknown (no BIOS version)'
        Get-Status -Installed 'N/A' -Target '1.50.0' | Should Be 'Unknown (no BIOS version)'
        Get-Status -Installed '1.50.0' -Target ''    | Should Be 'Unknown (no baseline)'
    }

    It 'never calls an unreadable or unscorable version Current' {
        foreach ($s in @((Get-Status -Installed '' -Target '1.50.0'),
                         (Get-Status -Installed 'garbage' -Target '1.50.0'),
                         (Get-Status -Installed '1.50.0' -Target ''))) {
            $s | Should Not Be 'Current'
        }
    }

    # audit 2026-07-25 (fable re-audit follow-up): an unparseable HOST string and an
    # unparseable CATALOG target both used to read 'Unknown (version format)', and the
    # roll-up told the operator "the baseline is fine, investigate the host" for both -
    # the exact opposite action for a typo'd catalog entry.
    It 'names the HOST as the unparseable side when the BIOS string is junk' {
        Get-Status -Installed 'garbage' -Target '1.50.0' | Should Be 'Unknown (host version format)'
    }

    It 'names the BASELINE as the unparseable side when the catalog target is junk' {
        Get-Status -Installed '1.50.0' -Target 'TBD - ask vendor' | Should Be 'Unknown (baseline version format)'
    }

    It 'stays generic when BOTH sides are unparseable (neither is provably at fault)' {
        Get-Status -Installed 'garbage' -Target 'TBD' | Should Be 'Unknown (version format)'
    }
}

# audit 2026-07-25 (fable re-audit follow-up): the 1.1.0 cancel-progress fix shipped with
# NO test. Operator-cancel used to bump $done WITHOUT emitting a progress event, so the
# strip froze at its last pre-cancel count while cancelled rows kept landing - the run
# read as wedged rather than cancelled. The scan block is swapped for one that never
# returns, so the harvest loop is guaranteed to reach the cancel branch (no real host,
# no TCP connect, no WinRM).
Describe 'operator cancel keeps the progress strip moving (audit 2026-07-25)' {

    $script:CancelEvents = New-Object System.Collections.ArrayList
    $script:CancelRun = & $script:Mod {
        param($em)
        $orig = $script:BiosFirmwareScanBlock
        Set-Variable -Name BiosFirmwareScanBlock -Scope script -Value {
            param([string]$Computer, $Cred, [string]$Auth)
            Start-Sleep -Seconds 12
            return @{ Host=$Computer; Online=$false; Error='never harvested' }
        }
        try {
            $job = @{ Cancel = $true }   # already cancelled: the first harvest pass takes the branch
            Invoke-JanetToolAction -ActionId 'scan-bios' `
                -Params @{ targets = 'WS-CANCEL-1,WS-CANCEL-2,WS-CANCEL-3'; threads = 3; '__job' = $job } `
                -Credential $null -Emit $em
        } finally { Set-Variable -Name BiosFirmwareScanBlock -Scope script -Value $orig }
    } { param($e) [void]$script:CancelEvents.Add($e) }

    It 'emits one progress event per abandoned host and finishes at done = total' {
        $prog = @($script:CancelEvents | Where-Object { $_.type -eq 'progress' })
        $prog.Count | Should Be 3
        [int]$prog[-1].done  | Should Be 3
        [int]$prog[-1].total | Should Be 3
    }

    It 'still emits a cancelled row per host and a cancel warning' {
        $rows = @($script:CancelEvents | Where-Object { $_.type -eq 'row' })
        $rows.Count | Should Be 3
        @($rows | Where-Object { [string]$_.Error -eq 'cancelled by operator' }).Count | Should Be 3
        @($script:CancelEvents | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and $_.text -match 'cancelled by operator' }).Count | Should Not Be 0
    }
}

Describe 'Manifest' {

    It 'declares the bumped version and stays read-only' {
        $man = & $script:Mod { Get-JanetToolManifest }
        $man.version | Should Be '1.1.1'
        foreach ($a in $man.actions) { $a.destructive | Should Be $false }
    }
}
