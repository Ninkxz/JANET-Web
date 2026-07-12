# =============================================================================
#  SelfGuard.HostIsSelf.Tests.ps1 - Pester 3.4 tests locking the self-guard
#  GUARD FUNCTION end-to-end (behavioral sibling of SelfGuard.IdentityParity.
#  Tests.ps1, which pins the identity SET the guard is built on; this file pins
#  what the guard FUNCTION actually returns for a battery of inputs).
#
#  Each of the 12 dispatcher modules ships a "Test-*HostIsSelf"-shaped guard
#  that decides whether a target token names the box JANET itself is running
#  on, so state-changing actions never get pointed at the dispatcher host.
#  This file drives each module's guard directly (in the module's own session
#  state, same discovery pattern as the parity test) with:
#    - exact self                         ($env:COMPUTERNAME)            -> true
#    - case-variant self (loop-3 P2)       (.ToUpper() AND .ToLower())    -> true
#    - '127.0.0.1', 'localhost', '::1'                                   -> true
#    - a foreign host ('DEFINITELY-NOT-THIS-BOX-zzq9')                   -> false
#    - a blank target ('')                                               -> false*
#  One It per module (12 total) so a single regressing module is pinpointed by
#  name instead of aborting the whole file.
#
#  DISCOVERY: mirrors SelfGuard.IdentityParity.Tests.ps1's solved gotcha -
#  Pester 3.4 runs every It in this file in the SAME PowerShell process, these
#  modules do not restrict exports, so importing module N leaks its guard into
#  Global scope and an unfiltered "-First 1" off Get-Command can silently grab
#  a PRIOR module's leaked function instead of this module's own. The fix is
#  identical: discover with `& $mod { Get-Command ... }` (inside the module's
#  own session state) and filter candidates to "$_.ModuleName -eq $mod.Name".
#
#  NAMING GOTCHA (verified live, not assumed): 11 of the 12 guards are in fact
#  named "Test-*HostIsSelf" (Test-AcasHostIsSelf, Test-JanetBetaHostIsSelf,
#  Test-JanetC2cHostIsSelf, Test-JanetCertDeployHostIsSelf, Test-PkgHostIsSelf,
#  Test-RemoteAdminHostIsSelf, Test-JanetHostIsSelf, Test-JanetSbeHostIsSelf,
#  Test-UprHostIsSelf, Test-WinUpgradeHostIsSelf, Test-WptHostIsSelf) - but
#  winrmbridge's guard is named "Test-WinRmBridgeSelfTarget" (no "HostIsSelf"
#  in it at all). A literal 'Test-*HostIsSelf' wildcard would silently find
#  ZERO candidates for winrmbridge and fail the "$fnName | Should Not
#  BeNullOrEmpty" guard-rail below. This file therefore discovers with the
#  wider 'Test-*Self*' wildcard, which was verified (via grep across all 12
#  modules) to still resolve to exactly ONE function per module.
#
#  *BLANK-INPUT GOTCHA (verified live, not assumed): 11 of the 12 guards open
#  with `if ([string]::IsNullOrWhiteSpace($Target)) { return $false }`, so a
#  blank target is explicitly NOT self. winrmbridge's guard instead opens with
#  `if (-not $c) { return $true }` - i.e. it fails CLOSED (treats a blank
#  target as self, so a caller that forgets to fill in a target can never
#  accidentally bridge/act against "nothing" by falling through to some other
#  branch). This is a real, intentional asymmetry in the shipped code, not a
#  bug this file is hiding: the winrmbridge It below asserts blank -> $true
#  and says why; all 11 others assert blank -> $false.
#
#  Run:  Invoke-Pester -Path .\tests\SelfGuard.HostIsSelf.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent

$script:HostIsSelfModules = @(
    @{ Name = 'acas';        File = 'JanetWeb.acas.psm1';        BlankExpected = $false }
    @{ Name = 'beta';        File = 'JanetWeb.beta.psm1';        BlankExpected = $false }
    @{ Name = 'c2c';         File = 'JanetWeb.c2c.psm1';         BlankExpected = $false }
    @{ Name = 'certdeploy';  File = 'JanetWeb.certdeploy.psm1';  BlankExpected = $false }
    @{ Name = 'pkginstall';  File = 'JanetWeb.pkginstall.psm1';  BlankExpected = $false }
    @{ Name = 'remoteadmin'; File = 'JanetWeb.remoteadmin.psm1'; BlankExpected = $false }
    @{ Name = 'restart';     File = 'JanetWeb.restart.psm1';     BlankExpected = $false }
    @{ Name = 'secureboot';  File = 'JanetWeb.secureboot.psm1';  BlankExpected = $false }
    @{ Name = 'upr';         File = 'JanetWeb.upr.psm1';         BlankExpected = $false }
    @{ Name = 'winrmbridge'; File = 'JanetWeb.winrmbridge.psm1'; BlankExpected = $true  }
    @{ Name = 'winupgrade';  File = 'JanetWeb.winupgrade.psm1';  BlankExpected = $false }
    @{ Name = 'wpt';         File = 'JanetWeb.wpt.psm1';         BlankExpected = $false }
)

Describe 'Self-guard Test-*HostIsSelf behavior - all 12 modules correctly classify self vs. foreign targets' {

    foreach ($spec in $script:HostIsSelfModules) {
        $modName = $spec.Name
        $modFile = $spec.File
        $blankExpected = $spec.BlankExpected

        It "$modName : Test-*HostIsSelf discovers and correctly classifies exact/case-variant self, loopback literals, a foreign host, and blank" {

            $modPath = Join-Path $script:Root ('modules\' + $modFile)
            $mod = Import-Module $modPath -Force -PassThru

            # Discover the guard INSIDE the module's own session state, filtered to this
            # module's own name so an earlier-imported module's leaked function of the same
            # wildcard shape can never be mistaken for this one's (see header comment).
            # Widened to 'Test-*Self*' (not 'Test-*HostIsSelf') because winrmbridge's guard
            # is named Test-WinRmBridgeSelfTarget - verified to still be a unique match.
            $candidates = & $mod { Get-Command -CommandType Function -Name 'Test-*Self*' }
            $fnName = ($candidates | Where-Object { $_.ModuleName -eq $mod.Name } | Select-Object -First 1).Name

            # A module that LOST its guard (renamed/deleted) must fail loudly here, not
            # silently skip the rest of this test.
            $fnName | Should Not BeNullOrEmpty

            # Build one reusable "call the discovered function with $Target" scriptblock and
            # invoke it in the module's own session state via "& $mod ..." for every probe.
            $invoke = [scriptblock]::Create('param($Target) ' + $fnName + ' $Target')

            $selfExact = [bool](& $mod $invoke $env:COMPUTERNAME)
            $selfExact | Should Be $true

            # Case-variant self (loop-3 P2 scenario): asserted BOTH directions so
            # case-insensitivity is exercised regardless of the box's stored casing.
            $selfUpper = [bool](& $mod $invoke ($env:COMPUTERNAME.ToUpper()))
            $selfUpper | Should Be $true

            $selfLower = [bool](& $mod $invoke ($env:COMPUTERNAME.ToLower()))
            $selfLower | Should Be $true

            $selfLoopbackIp   = [bool](& $mod $invoke '127.0.0.1')
            $selfLoopbackIp   | Should Be $true

            $selfLocalhost    = [bool](& $mod $invoke 'localhost')
            $selfLocalhost    | Should Be $true

            $selfLoopbackIpv6 = [bool](& $mod $invoke '::1')
            $selfLoopbackIpv6 | Should Be $true

            # A foreign host must NOT be classified as self.
            $foreign = [bool](& $mod $invoke 'DEFINITELY-NOT-THIS-BOX-zzq9')
            $foreign | Should Be $false

            # Blank target: 11/12 modules fail OPEN to "not self" (IsNullOrWhiteSpace ->
            # $false); winrmbridge fails CLOSED to "self" (-not $c -> $true). See header.
            $blank = [bool](& $mod $invoke '')
            $blank | Should Be $blankExpected
        }
    }
}
