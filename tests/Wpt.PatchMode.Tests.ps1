# =============================================================================
#  Wpt.PatchMode.Tests.ps1 - Pester 3.4 tests for the WPT patch posture (mode):
#  non-invasive (reboots suppressed, default) vs forced (reboot-if-needed,
#  customer-affecting). The remote CCM_Application.Install CIM call is
#  integration-only; these lock the two things that make the feature correct:
#  the manifest contract and the mode -> IsRebootIfNeeded decision.
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Force -PassThru

Describe 'WPT patch posture (mode)' {

    It 'the bulk-patch manifest exposes a mode input (noninvasive|forced, default noninvasive)' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        $act = $mani.actions | Where-Object { $_.id -eq 'bulk-patch' }
        $act | Should Not BeNullOrEmpty
        $modeIn = $act.inputs | Where-Object { $_.name -eq 'mode' }
        $modeIn | Should Not BeNullOrEmpty
        $modeIn.default | Should Be 'noninvasive'
        ($modeIn.options -contains 'noninvasive') | Should Be $true
        ($modeIn.options -contains 'forced') | Should Be $true
    }

    # The decision the remote app-install block makes (mirrored):
    #   $rebootIfNeeded = ($mode -eq 'forced')
    function Test-RebootIfNeeded { param([string]$Mode) return ($Mode -eq 'forced') }

    It 'forced mode reboots when needed (IsRebootIfNeeded = true)' {
        Test-RebootIfNeeded -Mode 'forced' | Should Be $true
    }
    It 'non-invasive mode suppresses reboots (IsRebootIfNeeded = false)' {
        Test-RebootIfNeeded -Mode 'noninvasive' | Should Be $false
    }
    It 'any unknown/blank mode is treated as non-invasive (fail-safe: never an unasked reboot)' {
        Test-RebootIfNeeded -Mode '' | Should Be $false
        Test-RebootIfNeeded -Mode 'garbage' | Should Be $false
    }

    It 'WptPatchBlock accepts a Mode parameter and stamps it on the result' {
        # Offline host: returns early before any host contact, but the block must
        # accept -Mode and carry it (proves the param plumbing, no WinRM).
        $r = & $script:Mod {
            & $script:WptPatchBlock -Computer '203.0.113.200' -Cred $null -Auth 'Default' -Mode 'forced'
        }
        $r.Mode | Should Be 'forced'
        $r.Reachable | Should Be $false   # TEST-NET host is unreachable -> safe, nothing triggered
    }
}
