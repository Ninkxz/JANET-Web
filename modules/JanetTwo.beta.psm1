# =============================================================================
#  JanetTwo.beta.psm1  ->  Beta Lab (tool id: 'beta')
#
#  Staging ground for experimental / in-development JANET TWO features. Each beta
#  feature is its own action with its own tab in web/js/views/beta.view.js; once a
#  feature is proven it graduates into its own real tool and is retired from here.
#
#  No beta sections are active right now - the earlier ones graduated out:
#    * App Versions / Software Inventory -> Workstation Patching (its Software
#      Manager + App Updater tabs already cover them).
#    * Logged-on user / last boot / pending-reboot -> the WPT Bulk Scan grid.
#
#  To add a beta section: add an action to Get-JanetToolManifest, a worker block,
#  a switch arm in Invoke-JanetToolAction, and a tab in web/js/views/beta.view.js
#  (the buildScanSection + TabHost pattern is in git history).
#
#  Contract: Get-JanetToolManifest / Invoke-JanetToolAction -> { rows; summary }.
#  PowerShell 5.1 only.
# =============================================================================

function Get-JanetToolManifest {
    @{
        id       = 'beta'
        name     = 'Beta Lab'
        version  = '0.5.0'
        category = 'Beta'
        summary  = 'Staging ground for experimental, read-only fleet features. No beta features are active right now - new ones land here as they bake, then graduate into their own tool.'
        actions  = @()
    }
}

function Invoke-JanetToolAction {
    param(
        [string]$ActionId,
        [hashtable]$Params,
        [System.Management.Automation.PSCredential]$Credential,
        [scriptblock]$Emit
    )
    $send = { param($e) if ($Emit) { & $Emit $e } }
    & $send @{ type='error'; text="Beta Lab has no active features (requested '$ActionId')." }
    return @{ rows=@(); summary=@{} }
}

Export-ModuleMember -Function Get-JanetToolManifest, Invoke-JanetToolAction
