# =============================================================================
#  Wpt.SpecExec.Tests.ps1 - Pester 3.4 for the wpt 6.6.3 spec-exec actions wired
#  to the SHARED speculative-execution mitigation engine
#  (modules\JanetWeb.specfix.psm1 - the ONE copy the ACAS Nemesis tool also calls).
#
#  PURE / offline unit scope - no real host, no WinRM, no registry write leaves
#  this box. We assert:
#   (a) the manifest exposes BOTH actions - spec-exec-scan (destructive=$false) and
#       spec-exec-enable (destructive=$true, with a confirm + targets input);
#   (b) the enable path SELF-GUARDS: a self-only target list drops before any
#       fan-out (no runspace pool, no remediation call);
#   (c) enable is FAIL-CLOSED: if the injected engine source is missing the action
#       aborts with no fan-out;
#   (d) shimmed STATEFUL registry: the enable ORs the BHI bit 0x800000 into
#       FeatureSettingsOverride, PRESERVING existing bits (0x2048 -> 0x802048), sets
#       Mask=3, reads back COMPLIANT and rolls up FIXED; an already-COMPLIANT state
#       rolls up NOCHANGE with NO write; the read-only verdicts (COMPLIANT / DRIFT /
#       VULNERABLE) hold and are OR-based (a host's Spectre/Meltdown bits don't matter).
#
#  Run:  Invoke-Pester -Path .\tests\Wpt.SpecExec.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$m   = Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1')     -Force -PassThru
$sfm = Import-Module (Join-Path $script:Root 'modules\JanetWeb.specfix.psm1') -Force -PassThru

# Drive the REAL wpt entry point in module scope, capturing every emitted event.
function Invoke-WptAction {
    param([string]$ActionId, [hashtable]$Params)
    $script:seEvents = New-Object System.Collections.ArrayList
    $emit = { param($e) [void]$script:seEvents.Add($e) }
    $res = & $m {
        param($aid, $prm, $em)
        Invoke-JanetToolAction -ActionId $aid -Params $prm -Credential $null -Emit $em
    } $ActionId $Params $emit
    return @{ Result = $res; Events = @($script:seEvents) }
}

# Drive the SHARED engine's remediation with a STATEFUL fake registry shimmed IN the
# specfix module scope: New-ItemProperty updates the fakes so the engine's read-back
# ($after) sees the write - exactly the round trip the real engine does. No real HKLM
# write ever happens. $Fso/$Mask set the pre-existing state ($null => value absent).
function Invoke-SpecEngineEnable {
    param($Fso, $Mask)
    & $sfm {
        param($Fso, $Mask)
        $script:__regFso = $Fso; $script:__regMask = $Mask
        $script:__writes = New-Object System.Collections.ArrayList
        function script:Get-CimInstance { param($ClassName, $Namespace, $Query, $Filter, $ErrorAction) [pscustomobject]@{ Name = 'AMD Test CPU' } }
        function script:Get-ItemProperty {
            param($Path, $Name, $ErrorAction)
            $v = if ($Name -eq 'FeatureSettingsOverride') { $script:__regFso } else { $script:__regMask }
            if ($null -eq $v) { throw 'absent (test)' }
            $o = New-Object psobject
            Add-Member -InputObject $o -MemberType NoteProperty -Name $Name -Value $v
            return $o
        }
        function script:Test-Path { param($Path, $LiteralPath, $ErrorAction) $true }
        function script:New-Item  { param($Path, [switch]$Force, $ErrorAction) }
        function script:New-ItemProperty {
            param($Path, $Name, $PropertyType, $Value, [switch]$Force, $ErrorAction)
            if ($Name -eq 'FeatureSettingsOverride') { $script:__regFso = [int]$Value } else { $script:__regMask = [int]$Value }
            [void]$script:__writes.Add(@{ Name = [string]$Name; Value = $Value })
        }
        $row = @(Invoke-JanetSpecExecRemediation)[0]
        [pscustomobject]@{ Result = [string]$row.Result; Action = [string]$row.Action; Detail = [string]$row.Detail; Writes = @($script:__writes); FinalFso = $script:__regFso; FinalMask = $script:__regMask }
    } $Fso $Mask
}

# Read-only state verdict with the two override values shimmed to a chosen pair.
function Get-SpecVerdict {
    param($Fso, $Mask)   # $null => value absent
    & $sfm {
        param($Fso, $Mask)
        $script:__fso = $Fso; $script:__mask = $Mask
        function script:Get-CimInstance { param($ClassName, $Namespace, $Query, $Filter, $ErrorAction) [pscustomobject]@{ Name = 'AMD Test CPU' } }
        function script:Get-ItemProperty {
            param($Path, $Name, $ErrorAction)
            $v = if ($Name -eq 'FeatureSettingsOverride') { $script:__fso } else { $script:__mask }
            if ($null -eq $v) { throw 'absent (test)' }
            $o = New-Object psobject
            Add-Member -InputObject $o -MemberType NoteProperty -Name $Name -Value $v
            return $o
        }
        [string]((Get-JanetSpecExecState).Verdict)
    } $Fso $Mask
}

Describe 'WPT 6.6.3 - spec-exec manifest actions (scan read-only, enable destructive)' {

    $manifest = & $m { Get-JanetToolManifest }

    It 'manifest version is at least 6.6.3 (spec-exec ship version)' {
        # Exact pins rot on every later bump; assert the floor.
        [version]$manifest.version -ge [version]'6.6.3' | Should Be $true
    }
    It 'spec-exec-scan is a NON-destructive read-only action with a targets input' {
        $a = @($manifest.actions | Where-Object { $_.id -eq 'spec-exec-scan' })[0]
        $a | Should Not BeNullOrEmpty
        [bool]$a.destructive | Should Be $false
        @($a.inputs | Where-Object { $_.name -eq 'targets' }).Count | Should Be 1
    }
    It 'spec-exec-enable is a destructive action with a confirm naming the 0x800000 OR + targets input' {
        $a = @($manifest.actions | Where-Object { $_.id -eq 'spec-exec-enable' })[0]
        $a | Should Not BeNullOrEmpty
        [bool]$a.destructive | Should Be $true
        [string]$a.confirm | Should Not BeNullOrEmpty
        [string]$a.confirm | Should Match '0x800000'
        @($a.inputs | Where-Object { $_.name -eq 'targets' }).Count | Should Be 1
    }
}

Describe 'WPT 6.6.3 - spec-exec-enable self-guard drops the dispatcher BEFORE fan-out' {

    # 127.0.0.1 is flagged self by Test-WptHostIsSelf, so it is the only target and
    # the self-guard must strip it: total=0 / selfSkipped=1, NO rows, and NO 'status'
    # start event (= no runspace pool, no remote registry write ever attempted).
    $out = Invoke-WptAction -ActionId 'spec-exec-enable' -Params @{ targets = '127.0.0.1' }

    It 'returns total=0 with selfSkipped=1 and no rows (self was the only target)' {
        [int]$out.Result.summary.total       | Should Be 0
        [int]$out.Result.summary.selfSkipped | Should Be 1
        @($out.Result.rows).Count            | Should Be 0
    }
    It 'emits a Self-guard warning naming the dropped host' {
        $warn = $out.Events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and $_.text -match 'Self-guard' }
        $warn | Should Not BeNullOrEmpty
    }
    It 'NEVER starts a fan-out (no status event = no pool / no remote enable)' {
        $starting = $out.Events | Where-Object { $_.type -eq 'status' }
        $starting | Should BeNullOrEmpty
    }
}

Describe 'WPT 6.6.3 - spec-exec-enable fails CLOSED when the engine source is missing' {

    # Blank the injected engine source in module scope, drive enable at a NON-self
    # target: the action must abort with an engine-unavailable summary and NO fan-out.
    & $m { $script:__savedSpecSrc = $script:SpecFixSrc; $script:SpecFixSrc = '' }
    $out = Invoke-WptAction -ActionId 'spec-exec-enable' -Params @{ targets = 'FAR-HOST-SE-1' }
    & $m { $script:SpecFixSrc = $script:__savedSpecSrc }

    It 'aborts with an engine-unavailable summary and no rows' {
        [string]$out.Result.summary.error | Should Be 'engine unavailable'
        @($out.Result.rows).Count         | Should Be 0
    }
    It 'never opens a fan-out (no "Enabling" status event)' {
        $started = $out.Events | Where-Object { $_.type -eq 'status' -and $_.text -match 'Enabling' }
        $started | Should BeNullOrEmpty
    }
    It 'logs a fail-closed error' {
        $err = $out.Events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'err' -and $_.text -match 'fail-closed' }
        $err | Should Not BeNullOrEmpty
    }
}

Describe 'WPT 6.6.3 - SHARED engine remediation (stateful shimmed registry, no real write)' {

    It 'a VULNERABLE state (value absent) -> enable ORs in 0x800000, sets Mask=3, reads back FIXED' {
        $r = Invoke-SpecEngineEnable -Fso $null -Mask $null
        $r.Result | Should Be 'FIXED'
        $r.Action | Should Be 'enable'
        @($r.Writes).Count | Should Be 2
        [int]$r.FinalFso  | Should Be 0x800000
        [int]$r.FinalMask | Should Be 3
        $r.Detail | Should Match 'REBOOT REQUIRED'
    }
    It 'a DRIFT state PRESERVES existing Spectre/Meltdown bits: 0x2048 -> 0x802048 (never a flat overwrite)' {
        $r = Invoke-SpecEngineEnable -Fso 0x2048 -Mask 3
        $r.Result | Should Be 'FIXED'
        [int]$r.FinalFso | Should Be 0x802048       # 0x2048 preserved, 0x800000 OR-ed in
    }
    It 'a DRIFT state with the wrong Mask -> enable corrects Mask to 3 and rolls up FIXED' {
        $r = Invoke-SpecEngineEnable -Fso 0x800000 -Mask 1
        $r.Result | Should Be 'FIXED'
        [int]$r.FinalFso  | Should Be 0x800000
        [int]$r.FinalMask | Should Be 3
    }
    It 'an already-COMPLIANT state -> NOCHANGE and performs NO write' {
        $r = Invoke-SpecEngineEnable -Fso 0x800000 -Mask 3
        $r.Result | Should Be 'NOCHANGE'
        @($r.Writes).Count | Should Be 0
    }
    It 'COMPLIANT with extra posture bits (0x802048 / Mask 3) -> NOCHANGE (BHI bit already present)' {
        $r = Invoke-SpecEngineEnable -Fso 0x802048 -Mask 3
        $r.Result | Should Be 'NOCHANGE'
        @($r.Writes).Count | Should Be 0
    }
}

Describe 'WPT 6.6.3 - SHARED engine read-only verdicts are OR-based on the 0x800000 bit' {

    It 'both values absent -> VULNERABLE'                      { (Get-SpecVerdict -Fso $null      -Mask $null) | Should Be 'VULNERABLE' }
    It 'BHI bit set, Mask=3 -> COMPLIANT'                      { (Get-SpecVerdict -Fso 0x800000   -Mask 3)     | Should Be 'COMPLIANT' }
    It 'BHI bit OR-ed with posture bits, Mask=3 -> COMPLIANT'  { (Get-SpecVerdict -Fso 0x802048   -Mask 3)     | Should Be 'COMPLIANT' }
    It 'posture bits but NO BHI bit -> DRIFT'                  { (Get-SpecVerdict -Fso 0x2048     -Mask 3)     | Should Be 'DRIFT' }
    It 'BHI bit set but Mask wrong -> DRIFT'                   { (Get-SpecVerdict -Fso 0x800000   -Mask 1)     | Should Be 'DRIFT' }
}
