# =============================================================================
#  SelfGuard.CaseInsensitive.Tests.ps1 - Pester 3.4
#
#  BEHAVIOURAL guard test (audit 2026-07-24, systemic finding S1).
#
#  Every destructive module builds a HashSet[string] of the names that mean
#  "this IS the JANET host" (shortname / FQDN / bound IPs / loopback) using
#  [StringComparer]::OrdinalIgnoreCase, caches it, and returns it. Returning it
#  as `return $set` makes PowerShell UNROLL the HashSet onto the output stream,
#  so the caller gets an Object[] whose .Contains() is ordinal CASE-SENSITIVE -
#  and the self-guard silently stops matching any target whose case differs from
#  $env:COMPUTERNAME. `return ,$set` (unary comma) suppresses the unroll.
#
#  On 2026-07-24 SEVEN of thirteen modules had the bare form and were bypassed
#  by a lowercase hostname - the case Tanium exports, import-pki-hosts and
#  hand-typed targets all supply. The whole 1640-test suite passed anyway,
#  because every existing self-guard test asserts static TEXT, not behaviour.
#
#  This file asserts BEHAVIOUR: the guard must recognise the local host in
#  lower, upper and as-reported case. Do not replace these with source-text
#  assertions - text assertions are exactly what missed the original bug.
#
#  Run:  Invoke-Pester -Path .\tests\SelfGuard.CaseInsensitive.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent

# module -> guard predicate that answers "does this token name the JANET host?"
$script:Guards = @(
    @{ Module = 'acas';        Predicate = 'Test-AcasHostIsSelf' }
    @{ Module = 'c2c';         Predicate = 'Test-JanetC2cHostIsSelf' }
    @{ Module = 'certdeploy';  Predicate = 'Test-JanetCertDeployHostIsSelf' }
    @{ Module = 'restart';     Predicate = 'Test-JanetHostIsSelf' }
    @{ Module = 'secureboot';  Predicate = 'Test-JanetSbeHostIsSelf' }
    @{ Module = 'winupgrade';  Predicate = 'Test-WinUpgradeHostIsSelf' }
    @{ Module = 'wpt';         Predicate = 'Test-WptHostIsSelf' }
    @{ Module = 'message';     Predicate = 'Test-JanetMessageHostIsSelf' }
    @{ Module = 'pkginstall';  Predicate = 'Test-PkgInstallHostIsSelf' }
    @{ Module = 'remoteadmin'; Predicate = 'Test-RemoteAdminHostIsSelf' }
    @{ Module = 'dhcp';        Predicate = 'Test-DhcpHostIsSelf' }
    @{ Module = 'upr';         Predicate = 'Test-UprHostIsSelf' }
)

$script:Cn = $env:COMPUTERNAME

Describe 'Self-guard recognises the local host regardless of case (audit 2026-07-24 S1)' {
    foreach ($g in $script:Guards) {
        $mod  = $g.Module
        $pred = $g.Predicate
        $path = Join-Path $script:Root ("modules\JanetWeb.{0}.psm1" -f $mod)

        It "$mod : $pred matches COMPUTERNAME in exact, lower and upper case" {
            $m = Import-Module $path -Force -PassThru
            $r = & $m ([scriptblock]::Create(@"
                [pscustomobject]@{
                    Exact = [bool]($pred '$($script:Cn)')
                    Lower = [bool]($pred '$($script:Cn.ToLower())')
                    Upper = [bool]($pred '$($script:Cn.ToUpper())')
                }
"@))
            $r.Exact | Should Be $true
            $r.Lower | Should Be $true   # <-- the 2026-07-24 regression: bare `return $set`
            $r.Upper | Should Be $true
        }
    }
}

Describe 'Self-guard identity set keeps its OrdinalIgnoreCase comparer (root cause)' {
    # The predicate test above is the one that matters; this pins the mechanism so
    # a failure points straight at the missing unary comma instead of at the caller.
    $getters = @(
        @{ Module = 'acas';        Getter = 'Get-AcasLocalIdentity' }
        @{ Module = 'c2c';         Getter = 'Get-JanetC2cLocalIdentity' }
        @{ Module = 'certdeploy';  Getter = 'Get-JanetCertDeployLocalIdentity' }
        @{ Module = 'restart';     Getter = 'Get-JanetLocalIdentity' }
        @{ Module = 'secureboot';  Getter = 'Get-JanetSbeLocalIdentity' }
        @{ Module = 'winupgrade';  Getter = 'Get-WinUpgradeLocalIdentity' }
        @{ Module = 'wpt';         Getter = 'Get-WptLocalIdentity' }
        @{ Module = 'message';     Getter = 'Get-JanetMessageLocalIdentity' }
        @{ Module = 'pkginstall';  Getter = 'Get-PkgInstallLocalIdentity' }
        @{ Module = 'remoteadmin'; Getter = 'Get-RemoteAdminLocalIdentity' }
        @{ Module = 'dhcp';        Getter = 'Get-DhcpLocalIdentity' }
        @{ Module = 'upr';         Getter = 'Get-UprLocalIdentity' }
    )
    foreach ($g in $getters) {
        $mod = $g.Module; $get = $g.Getter
        $path = Join-Path $script:Root ("modules\JanetWeb.{0}.psm1" -f $mod)

        It "$mod : $get returns a HashSet, not an unrolled array" {
            $m = Import-Module $path -Force -PassThru
            # Called twice on purpose: the cached early-return path unrolls just as
            # readily as the tail return, and only the tail was fixed the first time.
            $r = & $m ([scriptblock]::Create(@"
                `$first  = $get
                `$second = $get
                [pscustomobject]@{
                    FirstIsSet  = (`$first  -is [System.Collections.Generic.HashSet[string]])
                    SecondIsSet = (`$second -is [System.Collections.Generic.HashSet[string]])
                }
"@))
            $r.FirstIsSet  | Should Be $true
            $r.SecondIsSet | Should Be $true   # <-- the cached `return $script:X` path
        }
    }
}
