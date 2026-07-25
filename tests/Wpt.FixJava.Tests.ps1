# =============================================================================
#  Wpt.FixJava.Tests.ps1 - Pester 3.4 for the wpt 6.6.0 fix-java action wired to
#  the SHARED, vendor-gated Java remediation engine (modules\JanetWeb.javafix.psm1,
#  the ONE copy c2c's fix-java pillar also calls).
#
#  PURE / offline unit scope - no real host, no WinRM, no msiexec. We assert:
#   (a) the manifest exposes fix-java as destructive=$true at version 6.6.0;
#   (b) the dispatcher self-guard (Remove-WptSelfTargets) DROPS the JANET host
#       BEFORE any fan-out (so a Java uninstall can never hit this box);
#   (c) the SHARED engine carries the two security guards VERBATIM and they behave:
#         - vendor gate  '(?i)oracle|sun microsystems'  ACCEPTS Oracle/Sun, REJECTS
#           OpenJDK/Temurin/Corretto (so their JavaSoft residue is never pruned);
#         - strict-GUID  '^\{[0-9A-Fa-f-]+\}$'  REJECTS a malformed ProductCode
#           (so msiexec /x only ever runs on a well-formed GUID).
#
#  Run:  Invoke-Pester -Path .\tests\Wpt.FixJava.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$m  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Force -PassThru
$jm = Import-Module (Join-Path $script:Root 'modules\JanetWeb.javafix.psm1') -Force -PassThru

# Drive the REAL wpt entry point in module scope, capturing every emitted event.
function Invoke-WptAction {
    param([string]$ActionId, [hashtable]$Params)
    $script:fjEvents = New-Object System.Collections.ArrayList
    $emit = { param($e) [void]$script:fjEvents.Add($e) }
    $res = & $m {
        param($aid, $prm, $em)
        Invoke-JanetToolAction -ActionId $aid -Params $prm -Credential $null -Emit $em
    } $ActionId $Params $emit
    return @{ Result = $res; Events = @($script:fjEvents) }
}

Describe 'WPT 6.6.0 - fix-java manifest action (destructive, self-guarded utility)' {

    $manifest = & $m { Get-JanetToolManifest }

    It 'manifest version is at least 6.6.2 (fix-java ship version)' {
        # Exact pins rot on every later bump (this one broke at 6.6.3+); assert the floor.
        [version]$manifest.version -ge [version]'6.6.2' | Should Be $true
    }
    It 'fix-java is exposed as a destructive action with a confirm + targets input' {
        $a = @($manifest.actions | Where-Object { $_.id -eq 'fix-java' })[0]
        $a | Should Not BeNullOrEmpty
        [bool]$a.destructive | Should Be $true
        [string]$a.confirm | Should Not BeNullOrEmpty
        @($a.inputs | Where-Object { $_.name -eq 'targets' }).Count | Should Be 1
    }
}

Describe 'WPT 6.6.0 - fix-java self-guard drops the dispatcher host BEFORE fan-out' {

    # 127.0.0.1 is flagged self by Test-WptHostIsSelf, so it is the only target and
    # the self-guard must strip it, returning total=0 / selfSkipped=1 with NO fan-out
    # (no 'status' start event = no runspace pool ever opened, no host contact).
    $out = Invoke-WptAction -ActionId 'fix-java' -Params @{ targets = '127.0.0.1' }

    It 'returns total=0 with selfSkipped=1 and no rows (self was the only target)' {
        [int]$out.Result.summary.total       | Should Be 0
        [int]$out.Result.summary.selfSkipped | Should Be 1
        @($out.Result.rows).Count            | Should Be 0
    }
    It 'emits a Self-guard warning naming the dropped host' {
        $warn = $out.Events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and $_.text -match 'Self-guard' }
        $warn | Should Not BeNullOrEmpty
    }
    It 'NEVER starts a fan-out (no status event = no pool / no remote Java uninstall)' {
        $starting = $out.Events | Where-Object { $_.type -eq 'status' }
        $starting | Should BeNullOrEmpty
    }
}

Describe 'WPT 6.6.0 - shared engine security guards (verbatim in the source + behavior)' {

    $src = & $jm { Get-JanetJavaFixSrc }

    It 'the shared source is non-empty and defines Invoke-JanetJavaRemediation' {
        [string]$src | Should Not BeNullOrEmpty
        $src | Should Match 'function Invoke-JanetJavaRemediation'
    }

    # --- Vendor gate: '(?i)oracle|sun microsystems' ---------------------------
    $vendorRx = '(?i)oracle|sun microsystems'

    It 'the source carries the vendor gate regex verbatim' {
        $src | Should Match ([regex]::Escape($vendorRx))
    }
    It 'vendor gate ACCEPTS Oracle/Sun publishers (their old Java IS removed)' {
        'Oracle Corporation'       -match $vendorRx | Should Be $true
        'Oracle America, Inc.'     -match $vendorRx | Should Be $true
        'Sun Microsystems, Inc.'   -match $vendorRx | Should Be $true
    }
    It 'vendor gate REJECTS non-Oracle/Sun publishers (OpenJDK/Temurin/Corretto NEVER touched)' {
        'Eclipse Adoptium'         -match $vendorRx | Should Be $false
        'Amazon.com, Inc.'         -match $vendorRx | Should Be $false   # Corretto
        'Azul Systems, Inc.'       -match $vendorRx | Should Be $false   # Zulu OpenJDK
        'Microsoft'                -match $vendorRx | Should Be $false
    }

    # --- Strict-GUID msiexec guard: '^\{[0-9A-Fa-f-]+\}$' ---------------------
    $guidRx = '^\{[0-9A-Fa-f-]+\}$'

    It 'the source carries the strict-GUID guard regex verbatim' {
        $src | Should Match ([regex]::Escape($guidRx))
    }
    It 'strict-GUID guard ACCEPTS a well-formed ProductCode' {
        '{26A24AE4-039D-4CA4-87B4-2F86418064F0}' -match $guidRx | Should Be $true
    }
    It 'strict-GUID guard REJECTS a malformed ProductCode (msiexec /x never runs)' {
        'JavaSoft-8u281'      -match $guidRx | Should Be $false
        '{not a guid}'        -match $guidRx | Should Be $false
        '26A24AE4-039D'       -match $guidRx | Should Be $false   # no braces
        '{26A24AE4} extra'    -match $guidRx | Should Be $false
    }
}

Describe 'WPT - fix-java fails CLOSED when the engine returns no rollup row (audit 2026-07-24)' {

    # Behavioural: shadow the worker so the engine "answers" without a rollup row. That
    # used to default to NOCHANGE -> counted ok -> VulnPatched Success on a host the
    # engine never reported on. An absent verdict is not a clean verdict: it must read
    # FAIL, exactly as spec-exec-enable's identical branch already did.
    function Invoke-FixJavaWithWorker {
        param([string]$WorkerBody)
        & $m {
            param($body)
            $orig = $script:WptFixJavaBlock
            $script:WptFixJavaBlock = [scriptblock]::Create($body)
            try {
                $ev = New-Object System.Collections.ArrayList
                $emit = { param($e) [void]$ev.Add($e) }
                $res = Invoke-JanetToolAction -ActionId 'fix-java' -Params @{ targets='UNIT-JAVA-HOST'; threads=1 } -Credential $null -Emit $emit
                return @{ Summary = $res.summary; Rows = @($res.rows); Events = @($ev) }
            } finally { $script:WptFixJavaBlock = $orig }
        } $WorkerBody
    }
    function Get-JavaAudit($out) { @($out.Events | Where-Object { $_.type -eq 'audit' -and $_.target -eq 'UNIT-JAVA-HOST' })[0] }

    $hdr     = 'param($Computer,$Cred,$Auth,$Src) '
    $noRow   = Invoke-FixJavaWithWorker ($hdr + '@{ Host=$Computer; Reachable=$true; Rows=@(); Error="" }')
    $noChange= Invoke-FixJavaWithWorker ($hdr + '@{ Host=$Computer; Reachable=$true; Rows=@(@{ Result="NOCHANGE"; Detail="no Oracle/Sun Java older than 8u491" }); Error="" }')

    It 'an empty engine result reports FAIL, not NOCHANGE' {
        [string]@($noRow.Rows)[0].Result | Should Be 'FAIL'
    }
    It 'an empty engine result is NOT counted ok and audits Failure' {
        [int]$noRow.Summary.ok | Should Be 0
        [string](Get-JavaAudit $noRow).result    | Should Be 'Failure'
        [int](Get-JavaAudit $noRow).itemCount    | Should Be 0
    }
    It 'a real NOCHANGE verdict from the engine is still ok (clean host, nothing to remove)' {
        [string]@($noChange.Rows)[0].Result | Should Be 'NOCHANGE'
        [int]$noChange.Summary.ok           | Should Be 1
        [string](Get-JavaAudit $noChange).result | Should Be 'Success'
    }
}

Describe 'WPT - fix-java is reachable from the view (audit 2026-07-24)' {

    # The action was declared, self-guarded, confirm-gated and tested - but no operator
    # could run it: the view referenced neither it nor the two spec-exec actions.
    $viewSrc = Get-Content (Join-Path $script:Root 'web\js\views\wpt.view.js') -Raw

    It 'the view runs the fix-java action' {
        $viewSrc.Contains("'fix-java'") | Should Be $true
    }
    It 'the fix-java trigger is armed (typed confirmation), not a bare click' {
        ($viewSrc -match "confirmWord: 'JAVA'") | Should Be $true
    }
}

Describe 'WPT 6.6.0 - shared verdict heuristic honours the 1.8.0_491 bar (unchanged)' {

    It 'old Oracle Java is OLD; 8u491+ and modern JDKs are OK; junk is UNKNOWN' {
        (& $jm { Get-JanetJavaVerdict '1.8.0_281' }) | Should Be 'OLD'
        (& $jm { Get-JanetJavaVerdict '1.8.0_491' }) | Should Be 'OK'
        (& $jm { Get-JanetJavaVerdict '11.0.2' })    | Should Be 'OK'
        (& $jm { Get-JanetJavaVerdict 'banana' })    | Should Be 'UNKNOWN'
    }
}
