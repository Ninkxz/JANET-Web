# =============================================================================
#  Manifest.DestructiveFlag.Tests.ps1 - Pester 3.4 tests locking the
#  destructive-flag CONTRACT the loop-5 fail-closed session gate depends on.
#
#  The server gate (server\JanetWeb.Server.ps1) is now DEFAULT-DENY: an action
#  is treated as DESTRUCTIVE (requires an admin session) UNLESS its manifest
#  entry POSITIVELY asserts read-only via an explicit destructive=$false. A
#  read-only action that OMITS the flag would therefore be newly gated - a UX
#  regression - and a state-changing action that omits it is a security hole
#  only avoided because it, too, fails closed. Either way, an omitted flag is a
#  latent defect. This file pins the completeness contract: EVERY action of
#  EVERY module must declare an explicit boolean 'destructive' key, so a future
#  action can never reintroduce the omit-defaults-ambiguous state.
#
#  DISCOVERY (mirrors SelfGuard.IdentityParity.Tests.ps1): every tool module
#  exports the same Get-JanetToolManifest name, so each module is imported in
#  isolation (Import-Module -Force -PassThru) and its manifest is read INSIDE
#  that module's own session state via `& $mod { Get-JanetToolManifest }`, then
#  the module is removed before the next It. One It per module pinpoints a
#  single regressing module by name. Manifest actions are raw hashtables, so
#  key presence is tested with .ContainsKey - PSObject.Properties does NOT
#  surface hashtable keys.
#
#  Run:  Invoke-Pester -Path .\tests\Manifest.DestructiveFlag.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent

$script:ManifestModules = @(
    @{ Name = 'acas';         File = 'JanetWeb.acas.psm1' }
    @{ Name = 'adsearch';     File = 'JanetWeb.adsearch.psm1' }
    @{ Name = 'adto';         File = 'JanetWeb.adto.psm1' }
    @{ Name = 'beta';         File = 'JanetWeb.beta.psm1' }
    @{ Name = 'biosfirmware'; File = 'JanetWeb.biosfirmware.psm1' }
    @{ Name = 'c2c';          File = 'JanetWeb.c2c.psm1' }
    @{ Name = 'certdeploy';   File = 'JanetWeb.certdeploy.psm1' }
    @{ Name = 'dhcp';         File = 'JanetWeb.dhcp.psm1' }
    @{ Name = 'history';      File = 'JanetWeb.history.psm1' }
    @{ Name = 'kev';          File = 'JanetWeb.kev.psm1' }
    @{ Name = 'message';      File = 'JanetWeb.message.psm1' }
    @{ Name = 'patchlib';     File = 'JanetWeb.patchlib.psm1' }
    @{ Name = 'pkginstall';   File = 'JanetWeb.pkginstall.psm1' }
    @{ Name = 'remoteadmin';  File = 'JanetWeb.remoteadmin.psm1' }
    @{ Name = 'reports';      File = 'JanetWeb.reports.psm1' }
    @{ Name = 'restart';      File = 'JanetWeb.restart.psm1' }
    @{ Name = 'secureboot';   File = 'JanetWeb.secureboot.psm1' }
    @{ Name = 'sysadmin';     File = 'JanetWeb.sysadmin.psm1' }
    @{ Name = 'upr';          File = 'JanetWeb.upr.psm1' }
    @{ Name = 'winrmbridge';  File = 'JanetWeb.winrmbridge.psm1' }
    @{ Name = 'winupgrade';   File = 'JanetWeb.winupgrade.psm1' }
    @{ Name = 'wpt';          File = 'JanetWeb.wpt.psm1' }
)

Describe 'Manifest destructive-flag completeness - every action of every module declares an explicit boolean destructive key' {

    foreach ($spec in $script:ManifestModules) {
        $modName = $spec.Name
        $modFile = $spec.File

        It "$modName : every manifest action carries an explicit [bool] destructive flag (present, not `$null)" {

            $modPath = Join-Path $script:Root ('modules\' + $modFile)
            $mod = Import-Module $modPath -Force -PassThru

            $mani = & $mod { Get-JanetToolManifest }

            $mani            | Should Not BeNullOrEmpty
            $mani.actions    | Should Not BeNullOrEmpty

            $missing = @()
            $notBool = @()
            foreach ($act in $mani.actions) {
                $id = [string]$act.id
                $has = $false
                if ($act -is [System.Collections.IDictionary]) { $has = $act.ContainsKey('destructive') }
                elseif ($act.PSObject.Properties['destructive']) { $has = $true }

                if (-not $has) { $missing += $id; continue }
                $val = $act['destructive']
                if ($val -isnot [bool]) { $notBool += ("{0}={1}" -f $id, $val) }
            }

            # Fail loudly and name the offending action id(s) so a regressing
            # module is pinpointed to the exact action that dropped the flag.
            ($missing -join ', ') | Should BeNullOrEmpty
            ($notBool -join ', ') | Should BeNullOrEmpty

            Remove-Module ($mod.Name) -Force -ErrorAction SilentlyContinue
        }
    }
}
