# =============================================================================
#  JanetWeb.specfix.psm1  ->  SHARED, pool-injectable speculative-execution /
#  side-channel mitigation engine (Intel BHI CVE-2022-0001 - Tenable plugin 302873).
#
#  Same injection contract as JanetWeb.javafix.psm1: the engine is published as a
#  SOURCE STRING ($script:JanetSpecFixSrc, returned by Get-JanetSpecFixSrc) that
#  each bare pool worker runspace dot-sources; the same string is dot-sourced into
#  THIS module scope so the functions resolve for unit tests and module-scope callers.
#
#  Reused by the Workstation Patching Tool (spec-exec check + enable action) and the
#  ACAS Nemesis tool (one-click remediation for CVE-2022-0001 findings).
#
#  CORRECTNESS / SAFETY (must not be weakened):
#    * ENABLE = OR the BHI mitigation bit 0x00800000 INTO the existing
#      FeatureSettingsOverride value (never a flat overwrite) so the host's existing
#      Spectre/Meltdown posture bits are PRESERVED (0x48 HT-on / 0x2048 HT-off -> the
#      same value with 0x800000 added). Mask stays 3. This is the fleet-proven write
#      that actually clears Tenable plugin 302873 - a flat 0/8264 write does NOT clear
#      the finding and STRIPS the BHI bit off already-compliant hosts (proven on a
#      43-host fleet scan, ported from WorkstationPatchingTool RegKeyFixCatalog['BHI']).
#    * COMPLIANT = FeatureSettingsOverride has 0x00800000 set AND Mask == 3.
#    * FAIL-CLOSED: if the state helper is missing, nothing is written. The write is
#      read back and only reported FIXED when the readback is COMPLIANT.
#    * A REBOOT is required for the kernel to pick up the change.
#
#  Contract:
#    Get-JanetSpecFixSrc                    -> the injectable source string
#    Get-JanetSpecExecState                 -> @{ Cpu; IsIntel; Fso; Mask; Verdict }
#                                              Verdict: COMPLIANT|DRIFT|VULNERABLE
#    Invoke-JanetSpecExecRemediation        -> one 'SpecExec' rollup row
#                                              @{ Name; Action; Result; Detail }
# =============================================================================

$script:JanetSpecFixSrc = @'
# Read-only BHI (CVE-2022-0001) mitigation state. Compliance is what Tenable plugin
# 302873 audits: FeatureSettingsOverride carries the BHI bit 0x00800000 AND
# FeatureSettingsOverrideMask == 3. The BHI bit is OR-checked so a host's existing
# Spectre/Meltdown posture bits (e.g. 0x48, 0x2048) do not affect the verdict.
function Get-JanetSpecExecState {
    $mm  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
    $bhi = 0x00800000
    $cpu = ''
    try { $cpu = [string]((Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1).Name) } catch {}
    $fso = $null; $mask = $null
    try { $fso  = (Get-ItemProperty -Path $mm -Name FeatureSettingsOverride     -ErrorAction Stop).FeatureSettingsOverride }     catch {}
    try { $mask = (Get-ItemProperty -Path $mm -Name FeatureSettingsOverrideMask -ErrorAction Stop).FeatureSettingsOverrideMask } catch {}
    $hasBit = ($null -ne $fso)  -and (((([int]$fso)  -band $bhi) -eq $bhi))
    $maskOk = ($null -ne $mask) -and (([int]$mask) -eq 3)
    if ($hasBit -and $maskOk) {
        $verdict = 'COMPLIANT'
    } elseif ($null -eq $fso) {
        $verdict = 'VULNERABLE'   # value absent - BHI mitigation bit never set
    } else {
        $verdict = 'DRIFT'        # value present but BHI bit missing or Mask != 3
    }
    [pscustomobject]@{ Cpu=$cpu; IsIntel=($cpu -match '(?i)intel'); Fso=$fso; Mask=$mask; Verdict=$verdict }
}

# Enable the BHI mitigation by OR-ing 0x00800000 into FeatureSettingsOverride
# (PRESERVING existing bits) and setting FeatureSettingsOverrideMask=3. Idempotent
# (already-COMPLIANT -> NOCHANGE). The write is read back; FIXED only on a COMPLIANT
# readback. REBOOT REQUIRED to apply. Returns one rollup row.
function Invoke-JanetSpecExecRemediation {
    if (-not (Get-Command Get-JanetSpecExecState -ErrorAction SilentlyContinue)) {
        return ,([pscustomobject]@{ Name='SpecExec'; Action='none'; Result='FAIL'; Detail='state helper unavailable on target - nothing changed (fail-closed)' })
    }
    $bhi = 0x00800000
    $mm  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
    $before = Get-JanetSpecExecState
    if ($before.Verdict -eq 'COMPLIANT') {
        return ,([pscustomobject]@{ Name='SpecExec'; Action='none'; Result='NOCHANGE'; Detail="BHI mitigation already set (FeatureSettingsOverride=0x$('{0:X}' -f [int]$before.Fso), Mask=$($before.Mask)) - no change." })
    }
    $curFso = 0; if ($null -ne $before.Fso) { $curFso = [int]$before.Fso }
    $newFso = $curFso -bor $bhi
    try {
        if (-not (Test-Path $mm)) { New-Item -Path $mm -Force -ErrorAction Stop | Out-Null }
        New-ItemProperty -Path $mm -Name FeatureSettingsOverride     -PropertyType DWord -Value $newFso -Force -ErrorAction Stop | Out-Null
        New-ItemProperty -Path $mm -Name FeatureSettingsOverrideMask -PropertyType DWord -Value 3       -Force -ErrorAction Stop | Out-Null
    } catch {
        return ,([pscustomobject]@{ Name='SpecExec'; Action='enable'; Result='FAIL'; Detail="registry write failed: $($_.Exception.Message)" })
    }
    $after = Get-JanetSpecExecState
    if ($after.Verdict -eq 'COMPLIANT') {
        return ,([pscustomobject]@{ Name='SpecExec'; Action='enable'; Result='FIXED'; Detail="BHI bit 0x800000 OR-ed in (0x$('{0:X}' -f $curFso) -> 0x$('{0:X}' -f $newFso), Mask=3); existing Spectre/Meltdown bits preserved - REBOOT REQUIRED (was: $($before.Verdict))." })
    }
    return ,([pscustomobject]@{ Name='SpecExec'; Action='enable'; Result='FAIL'; Detail="wrote FeatureSettingsOverride=0x$('{0:X}' -f $newFso)/Mask=3 but readback is still $($after.Verdict) - verify manually." })
}
'@

# Dot-source the engine into THIS module scope so the functions resolve for
# module-scope callers and unit tests.
try { . ([scriptblock]::Create($script:JanetSpecFixSrc)) } catch {}

# The injectable source string, for pool workers that must dot-source it in a bare
# runspace with no module scope.
function Get-JanetSpecFixSrc { $script:JanetSpecFixSrc }

Export-ModuleMember -Function Get-JanetSpecFixSrc, Get-JanetSpecExecState, Invoke-JanetSpecExecRemediation
