# =============================================================================
#  JanetWeb.specfix.psm1  ->  SHARED, pool-injectable speculative-execution /
#  side-channel mitigation engine (Intel BHI CVE-2022-0001 + the Spectre/Meltdown
#  family that Windows gates behind the same registry switch).
#
#  Same injection contract as JanetWeb.javafix.psm1: the engine is published as a
#  SOURCE STRING ($script:JanetSpecFixSrc, returned by Get-JanetSpecFixSrc) that
#  each bare pool worker runspace dot-sources; the same string is dot-sourced into
#  THIS module scope so the functions resolve for unit tests and module-scope callers.
#
#  Reused by the Workstation Patching Tool (spec-exec check + enable action) and the
#  ACAS Nemesis tool (one-click remediation for CVE-2022-0001 / spec-exec findings) -
#  no copy-paste, so a future correction reaches both callers.
#
#  CORRECTNESS / SAFETY (must not be weakened):
#    * ENABLE target = Microsoft KB4073119 documented values: FeatureSettingsOverride=0
#      and FeatureSettingsOverrideMask=3 ("to enable the mitigations"). These are the
#      conservative ON values - NOT the more invasive 8264 variant that also disables
#      Hyper-Threading. Do not change without a documented reason.
#    * FAIL-CLOSED: if the state helper is missing on the target, nothing is written.
#    * NO FAKED VALIDATION: the BHI *hardware* mitigation additionally needs the OEM
#      microcode (Intel SA-00598) + a reboot, which a registry write cannot supply and
#      this engine never claims to. On an Intel CPU the Detail says so explicitly.
#
#  Contract:
#    Get-JanetSpecFixSrc                    -> the injectable source string
#    Get-JanetSpecExecState                 -> @{ Cpu; IsIntel; Fso; Mask; Verdict }
#                                              Verdict: ENABLED|DISABLED|PARTIAL|DEFAULT
#    Invoke-JanetSpecExecRemediation        -> one 'SpecExec' rollup row
#                                              @{ Name; Action; Result; Detail }
# =============================================================================

$script:JanetSpecFixSrc = @'
# Read-only speculative-execution mitigation state. Reads the two Memory Management
# override values that Windows uses to force the Spectre/Meltdown/BHI mitigations on
# or off. The values are a bitmask where a SET low bit DISABLES a mitigation, so the
# enabled state is Override&3==0 with Mask&3==3 (both low bits governed, both clear).
function Get-JanetSpecExecState {
    $mm  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
    $cpu = ''
    try { $cpu = [string]((Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1).Name) } catch {}
    $fso = $null; $mask = $null
    try { $fso  = (Get-ItemProperty -Path $mm -Name FeatureSettingsOverride     -ErrorAction Stop).FeatureSettingsOverride }     catch {}
    try { $mask = (Get-ItemProperty -Path $mm -Name FeatureSettingsOverrideMask -ErrorAction Stop).FeatureSettingsOverrideMask } catch {}
    if ($null -eq $fso -or $null -eq $mask) {
        $verdict = 'DEFAULT'          # not explicitly forced - OS default (BHI can be OFF without microcode + explicit enable)
    } elseif ((([int]$fso -band 3) -eq 0) -and (([int]$mask -band 3) -eq 3)) {
        $verdict = 'ENABLED'
    } elseif (([int]$fso -band 3) -ne 0) {
        $verdict = 'DISABLED'         # explicitly turned OFF by policy/registry
    } else {
        $verdict = 'PARTIAL'          # mask set but not the full low-bit pair
    }
    [pscustomobject]@{ Cpu=$cpu; IsIntel=($cpu -match '(?i)intel'); Fso=$fso; Mask=$mask; Verdict=$verdict }
}

# Enable the Spectre/Meltdown/BHI mitigations via the KB4073119 registry values.
# Idempotent (already-enabled -> NOCHANGE). Writes DWords FeatureSettingsOverride=0
# and FeatureSettingsOverrideMask=3. REBOOT REQUIRED to apply. Returns one rollup row.
function Invoke-JanetSpecExecRemediation {
    if (-not (Get-Command Get-JanetSpecExecState -ErrorAction SilentlyContinue)) {
        return ,([pscustomobject]@{ Name='SpecExec'; Action='none'; Result='FAIL'; Detail='state helper unavailable on target - nothing changed (fail-closed)' })
    }
    $before = Get-JanetSpecExecState
    $mm = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
    $intelNote = if ($before.IsIntel) { ' Intel CPU: the BHI *hardware* mitigation also needs OEM microcode (Intel SA-00598) + a reboot - the registry enable alone is not sufficient without microcode.' } else { '' }
    if ($before.Verdict -eq 'ENABLED') {
        return ,([pscustomobject]@{ Name='SpecExec'; Action='none'; Result='NOCHANGE'; Detail="mitigations already explicitly enabled (FeatureSettingsOverride=$($before.Fso), Mask=$($before.Mask)).$intelNote" })
    }
    try {
        if (-not (Test-Path $mm)) { New-Item -Path $mm -Force -ErrorAction Stop | Out-Null }
        New-ItemProperty -Path $mm -Name FeatureSettingsOverride     -PropertyType DWord -Value 0 -Force -ErrorAction Stop | Out-Null
        New-ItemProperty -Path $mm -Name FeatureSettingsOverrideMask -PropertyType DWord -Value 3 -Force -ErrorAction Stop | Out-Null
    } catch {
        return ,([pscustomobject]@{ Name='SpecExec'; Action='enable'; Result='FAIL'; Detail="registry write failed: $($_.Exception.Message)" })
    }
    return ,([pscustomobject]@{ Name='SpecExec'; Action='enable'; Result='FIXED'; Detail="mitigations enabled (FeatureSettingsOverride 0 / Mask 3) - REBOOT REQUIRED to apply (was: $($before.Verdict)).$intelNote" })
}
'@

# Dot-source the engine into THIS module scope so the functions resolve for
# module-scope callers and unit tests.
try { . ([scriptblock]::Create($script:JanetSpecFixSrc)) } catch {}

# The injectable source string, for pool workers that must dot-source it in a bare
# runspace with no module scope.
function Get-JanetSpecFixSrc { $script:JanetSpecFixSrc }

Export-ModuleMember -Function Get-JanetSpecFixSrc, Get-JanetSpecExecState, Invoke-JanetSpecExecRemediation
