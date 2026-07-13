# =============================================================================
#  Acas.RowVerdict.Tests.ps1 - Pester 3.4 for the ACAS update-row verdict cell
#  (loop19 P1). The async updaters (Chrome/Edge/Office /ua) trigger a BACKGROUND
#  update, so the on-disk version does not change in-session and the worker emits
#  a distinct "UNCONFIRMED: ..." token. $script:AcasOkOf excludes UNCONFIRMED from
#  the OK count (renders amber) - but the row-builder $script:AcasUpdateRowOf used
#  to fall UNCONFIRMED through to a green 'OK', so the per-host row cell said OK
#  while the banner + audit correctly said failed. This locks the row cell to the
#  count predicate: UNCONFIRMED -> 'UNCONFIRMED', never a false 'OK'.
#
#  Module-scope scriptblocks are invoked in the module session state (`& $mod {}`).
#
#  Run:  Invoke-Pester -Path .\tests\Acas.RowVerdict.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$mod = Import-Module (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Force -PassThru

function RowResult([string]$res) { & $mod { param($r) (& $script:AcasUpdateRowOf $r 'HOST-1' @{ Profile = 'TestProfile' }).Result } $res }
function OkOf([string]$res)      { & $mod { param($r) & $script:AcasOkOf $r } $res }

Describe 'ACAS update row verdict - UNCONFIRMED is amber, cell matches the OK-count predicate (loop19 P1)' {
    It 'an UNCONFIRMED result renders as UNCONFIRMED (not a false green OK)' {
        RowResult 'UNCONFIRMED: version unchanged after trigger' | Should Be 'UNCONFIRMED'
    }
    It 'a FAIL result renders FAIL' {
        RowResult 'FAIL: install threw' | Should Be 'FAIL'
    }
    It 'a SKIP result renders SKIP' {
        RowResult 'SKIP: already current' | Should Be 'SKIP'
    }
    It 'a genuine OK / version bump renders OK' {
        RowResult 'OK (120.0 -> 121.0)' | Should Be 'OK'
    }
    It 'the row cell NEVER shows OK for a result the count predicate rejects (consistency)' {
        foreach ($r in @('UNCONFIRMED: version unchanged', 'FAIL: boom')) {
            (OkOf $r)     | Should Be $false
            (RowResult $r) | Should Not Be 'OK'
        }
        # converse: a real OK is both counted OK and rendered OK
        (OkOf 'OK (bumped)')     | Should Be $true
        (RowResult 'OK (bumped)') | Should Be 'OK'
    }
}
