# =============================================================================
#  Dhcp.IpValidation.Tests.ps1 - Pester 3.4 for the DHCP tool's IP-validation
#  safety gate (loop16). dhcp is a DESTRUCTIVE tool (it writes scope-option values
#  and casts scope-ids to [ipaddress] on a remote DHCP server) yet had NO dedicated
#  test. Test-JanetIpv4 is the gate that stops a malformed/truncated IP from being
#  stored as an option value or reaching the remote [ipaddress] cast. Its whole point
#  is to reject the classful shorthand that .NET's lenient TryParse SILENTLY widens
#  ('192.168.1' -> 192.168.0.1, '10' -> 0.0.0.10) via a parse round-trip.
#
#  Internal (non-exported) helpers are exercised in the module's session state with
#  `& $mod { ... }` (same idiom as Message.SelfGuard.Tests.ps1) - no production change.
#
#  Run:  Invoke-Pester -Path .\tests\Dhcp.IpValidation.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$mod = Import-Module (Join-Path $script:Root 'modules\JanetWeb.dhcp.psm1') -Force -PassThru

function Ipv4([string]$t) { & $mod { param($x) Test-JanetIpv4 $x } $t }

Describe 'dhcp Test-JanetIpv4 - canonical dotted-quad only (destructive-write safety gate)' {
    It 'accepts canonical IPv4 addresses' {
        Ipv4 '192.168.1.1'     | Should Be $true
        Ipv4 '10.0.0.255'      | Should Be $true
        Ipv4 '0.0.0.0'         | Should Be $true
        Ipv4 '255.255.255.255' | Should Be $true
    }
    It 'trims surrounding whitespace' {
        Ipv4 '  10.1.2.3  ' | Should Be $true
    }
    It 'REJECTS classful shorthand that .NET TryParse silently widens' {
        # '192.168.1' -> 192.168.0.1 ; '10.1' -> 10.0.0.1 ; '10' -> 0.0.0.10. The
        # round-trip (ToString -eq trimmed input) must reject each so a truncated paste
        # never becomes a WRONG scope-id or option value on the destructive path.
        Ipv4 '192.168.1' | Should Be $false
        Ipv4 '10.1'      | Should Be $false
        Ipv4 '10'        | Should Be $false
    }
    It 'REJECTS non-canonical leading-zero / octal-looking octets' {
        # Regardless of how .NET interprets a leading zero, the round-trip differs -> reject.
        Ipv4 '010.0.0.1' | Should Be $false
        Ipv4 '1.2.3.04'  | Should Be $false
    }
    It 'REJECTS out-of-range octets and garbage' {
        Ipv4 '256.1.1.1' | Should Be $false
        Ipv4 '1.2.3.4.5' | Should Be $false
        Ipv4 'abc'       | Should Be $false
        Ipv4 ''          | Should Be $false
        Ipv4 '   '       | Should Be $false
    }
    It 'REJECTS IPv6 (this is an IPv4-only gate)' {
        Ipv4 '::1'     | Should Be $false
        Ipv4 'fe80::1' | Should Be $false
    }
}

Describe 'dhcp Get-JanetValidIpList - split / validate / canonicalize / dedupe' {
    It 'splits a mixed blob into valid (deduped, in order) and invalid' {
        $r = & $mod { param($b) Get-JanetValidIpList $b } "10.0.0.1, 10.0.0.1`n192.168.1; bogus 10; 172.16.0.5"
        (@($r.Valid)   -join ',') | Should Be '10.0.0.1,172.16.0.5'
        (@($r.Invalid) -join ',') | Should Be '192.168.1,bogus,10'
    }
    It 'returns empty arrays for an all-invalid blob (no crash)' {
        $r = & $mod { param($b) Get-JanetValidIpList $b } 'nope; 999.1.1.1'
        @($r.Valid).Count | Should Be 0
        (@($r.Invalid) -join ',') | Should Be 'nope,999.1.1.1'
    }
}
