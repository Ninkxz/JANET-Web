# =============================================================================
#  Upr.M365Scope.Tests.ps1 - Pester 3.4 test for the Microsoft 365 scoping fix
#  (audit 2026-07-24). The real removal runs inside a remote scriptblock, so
#  this mirrors the two decisions that guarantee we remove ONLY the selected
#  Click-to-Run product: (a) resolving the C2R product ID / culture from the
#  candidate's OWN registry key name or uninstall string, and (b) building the
#  setup.exe /configure XML from it. FAILS on the old behaviour, which wrote a
#  bare <Remove All="TRUE"/> and wiped every C2R Office product on the host.
#  Pure logic, no registry / no setup.exe.
# =============================================================================

# Mirror of the resolver in JanetWeb.upr.psm1 M365 handler.
function Resolve-M365SelectedProduct {
    param([string]$ChildName, [string]$UnStr)
    $id = $null; $cul = $null
    if ($ChildName -match '^\s*(?<id>[A-Za-z0-9_]+)\s*-\s*(?<cul>[A-Za-z]{2,3}-[A-Za-z0-9\-]{2,12})\s*$') {
        $id = $Matches['id']; $cul = $Matches['cul']
    }
    if (-not $id -and $UnStr -match '(?i)productstoremove=(?<id>[A-Za-z0-9_]+)\.\d+_(?<cul>[A-Za-z]{2,3}-[A-Za-z0-9\-]+?)_') {
        $id = $Matches['id']; $cul = $Matches['cul']
    }
    if (-not $id -and $UnStr -match '(?i)productstoremove=(?<id>[A-Za-z0-9_]+)') { $id = $Matches['id'] }
    if (-not $cul -and $UnStr -match '(?i)\bculture=(?<cul>[A-Za-z]{2,3}-[A-Za-z0-9\-]+)') { $cul = $Matches['cul'] }
    [pscustomobject]@{ ProductId = $id; Culture = $cul }
}

# Mirror of the config-XML build. $null ProductId => the handler stages NOTHING
# (fail closed), so this returns $null rather than a fleet-wide Remove All.
function New-M365RemoveConfigXml {
    param([string]$ProductId, [string]$Culture)
    if (-not $ProductId) { return $null }
    $langXml = if ($Culture) { '<Language ID="{0}"/>' -f $Culture } else { '' }
    '<Configuration><Remove><Product ID="{0}">{1}</Product></Remove><Display Level="None" AcceptEULA="TRUE"/><Property Name="FORCEAPPSHUTDOWN" Value="TRUE"/></Configuration>' -f $ProductId, $langXml
}

Describe 'UPR M365 removal scopes to the selected C2R product (audit 2026-07-24)' {

    It 'resolves the product ID + culture from the C2R ARP key name' {
        $p = Resolve-M365SelectedProduct -ChildName 'O365ProPlusRetail - en-us' -UnStr ''
        $p.ProductId | Should Be 'O365ProPlusRetail'
        $p.Culture   | Should Be 'en-us'
    }

    It 'resolves the product ID + culture from the C2R uninstall string' {
        $un = '"C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeClickToRun.exe" scenario=install scenariosubtype=ARP sourcetype=None productstoremove=ProjectProRetail.16_en-us_x-none culture=en-us'
        $p = Resolve-M365SelectedProduct -ChildName 'ProjectProRetail' -UnStr $un
        $p.ProductId | Should Be 'ProjectProRetail'
        $p.Culture   | Should Be 'en-us'
    }

    It 'generates config XML naming ONLY the selected product' {
        $p   = Resolve-M365SelectedProduct -ChildName 'O365ProPlusRetail - en-us' -UnStr ''
        $xml = New-M365RemoveConfigXml -ProductId $p.ProductId -Culture $p.Culture
        ($xml -match '<Product ID="O365ProPlusRetail">') | Should Be $true
        ($xml -match '<Language ID="en-us"/>')           | Should Be $true
    }

    It 'NEVER emits a bare Remove All (the old fleet-wide wipe)' {
        $p   = Resolve-M365SelectedProduct -ChildName 'O365ProPlusRetail - en-us' -UnStr ''
        $xml = New-M365RemoveConfigXml -ProductId $p.ProductId -Culture $p.Culture
        # The old handler wrote '<Configuration><Remove All="TRUE"/>...' - that
        # attribute is what removed EVERY C2R Office product on the host.
        ($xml -match '(?i)Remove\s+All\s*=')      | Should Be $false
        ($xml -match '(?i)<Remove\s*/>')          | Should Be $false
        # The only legal Remove form here is the scoped container.
        ($xml -match '<Remove><Product ID="')     | Should Be $true
    }

    It 'does not name a sibling C2R product the operator did not select' {
        $p   = Resolve-M365SelectedProduct -ChildName 'VisioProRetail - en-us' -UnStr ''
        $xml = New-M365RemoveConfigXml -ProductId $p.ProductId -Culture $p.Culture
        ($xml -match 'VisioProRetail')      | Should Be $true
        ($xml -match 'O365ProPlusRetail')   | Should Be $false
        ($xml -match 'ProjectProRetail')    | Should Be $false
    }

    It 'omits the Language element (removes all languages of THAT product) when culture is unknown' {
        $xml = New-M365RemoveConfigXml -ProductId 'O365ProPlusRetail' -Culture $null
        ($xml -match '<Product ID="O365ProPlusRetail"></Product>') | Should Be $true
        ($xml -match 'Language')                                  | Should Be $false
    }

    It 'returns NOTHING to stage (fail closed) when no product ID is resolvable' {
        $p = Resolve-M365SelectedProduct -ChildName 'Microsoft Office 365 ProPlus' -UnStr 'setup.exe /uninstall'
        $p.ProductId | Should BeNullOrEmpty
        $xml = New-M365RemoveConfigXml -ProductId $p.ProductId -Culture $p.Culture
        $xml | Should BeNullOrEmpty
    }
}
