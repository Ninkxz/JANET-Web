# =============================================================================
#  Acas.SpecExec.Tests.ps1 - Pester 3.4 for the ACAS Nemesis 1.11.3 Spectre/BHI
#  (CVE-2022-0001) ENABLE remediation, wired to the SHARED speculative-execution
#  mitigation engine (modules\JanetWeb.specfix.psm1 - the ONE copy wpt's spec-exec
#  actions also call). No fork.
#
#  PURE / offline unit scope - no real host, no WinRM, no registry write. We assert:
#   (a) the acas manifest loads at 1.11.3;
#   (b) a new 'Spectre/BHI Mitigation - Enable (CVE-2022-0001)' profile exists, is
#       flagged NeedsSpecFix + ForbidSelf, and its Script calls the SHARED
#       Invoke-JanetSpecExecRemediation (never a forked copy of the write logic);
#   (c) CVE-2022-0001 / branch-target-injection findings map to that profile;
#   (d) the dispatch DROPS the dispatcher host BEFORE fan-out for the enable path
#       (self-guard: a reboot-required registry write can never hit the JANET box);
#   (e) the shared engine source is injected into the pool worker and the worker
#       fails CLOSED (a FAIL, no action) when the source is empty/absent.
#
#  Run:  Invoke-Pester -Path .\tests\Acas.SpecExec.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$sfm = Import-Module (Join-Path $script:Root 'modules\JanetWeb.specfix.psm1') -Force -PassThru
$mod = Import-Module (Join-Path $script:Root 'modules\JanetWeb.acas.psm1')    -Force -PassThru

$SpecProfile = 'Spectre/BHI Mitigation - Enable (CVE-2022-0001)'

Describe 'ACAS 1.11.3 - manifest loads at the bumped version' {
    $manifest = & $mod { Get-JanetToolManifest }
    It 'manifest id is acas and version is 1.11.4' {
        [string]$manifest.id      | Should Be 'acas'
        [string]$manifest.version | Should Be '1.11.4'
    }
}

Describe 'ACAS 1.11.3 - Spectre/BHI ENABLE profile exists and uses the SHARED engine' {

    It 'the enable profile is registered in the App Update profile table' {
        $p = & $mod { param($n) $script:AcasUpdateProfiles[$n] } $SpecProfile
        $p | Should Not BeNullOrEmpty
    }
    It 'the enable profile is flagged NeedsSpecFix + ForbidSelf (engine-injected, self-forbidden)' {
        $flags = & $mod {
            param($n)
            $p = $script:AcasUpdateProfiles[$n]
            [pscustomobject]@{ NeedsSpecFix = [bool]$p['NeedsSpecFix']; ForbidSelf = [bool]$p['ForbidSelf'] }
        } $SpecProfile
        $flags.NeedsSpecFix | Should Be $true
        $flags.ForbidSelf   | Should Be $true
    }
    It 'its Script calls the SHARED Invoke-JanetSpecExecRemediation (not a forked copy of the write logic)' {
        $txt = & $mod { param($n) $script:AcasUpdateProfiles[$n].Script.ToString() } $SpecProfile
        $txt | Should Match 'Invoke-JanetSpecExecRemediation'
        # A fork would re-implement the KB4073119 registry write here; it must NOT.
        $txt | Should Not Match 'New-ItemProperty'
        $txt | Should Not Match 'FeatureSettingsOverride'
    }
    It 'the shared engine SOURCE is captured at module load for pool injection' {
        $len = & $mod { ($script:AcasSpecFixSrc).Length }
        [int]$len | Should BeGreaterThan 0
    }
    It 'the captured source defines the KB4073119 remediation (single source of truth)' {
        $src = & $sfm { Get-JanetSpecFixSrc }
        $src | Should Match 'function Invoke-JanetSpecExecRemediation'
        $src | Should Match 'FeatureSettingsOverride'
        $src | Should Match 'FeatureSettingsOverrideMask'
    }
}

Describe 'ACAS 1.11.3 - CVE-2022-0001 / branch-target-injection findings map to the enable profile' {

    It 'the match table routes CVE-2022-0001 / BHI keywords to the enable profile' {
        $profiles = & $mod {
            @(Get-AcasProfileMatchTable | Where-Object { $_.Keywords -contains 'CVE-2022-0001' })[0].Profiles
        }
        @($profiles) -contains $SpecProfile | Should Be $true
    }
    It 'a branch-target-injection finding surfaces the enable profile (Patchable)' {
        $g = & $mod {
            $f = @([pscustomobject]@{ Host='WS-9'; PluginId='2'; PluginName='Intel CPU Branch History Injection (BHI) - CVE-2022-0001'; Severity='Medium'; Cve='CVE-2022-0001'; Solution='' })
            @(Get-AcasVulnGroups -Findings $f)[0]
        }
        $g.Category                            | Should Be 'Patchable'
        @($g.ProfileNames) -contains $SpecProfile | Should Be $true
    }
}

Describe 'ACAS 1.11.3 - self-guard DROPS the dispatcher before fan-out for the enable path' {

    It 'the enable profile is ForbidSelf' {
        (& $mod { param($n) Get-AcasProfileForbidsSelf $n } $SpecProfile) | Should Be $true
    }
    It 'Select-AcasNonSelfHosts strips THIS box from an enable wave, keeping foreign hosts' {
        $out = & $mod {
            param($n)
            @(Select-AcasNonSelfHosts -ProfileName $n -Hosts @($env:COMPUTERNAME, 'FAR-HOST-SE') -Send { param($e) })
        } $SpecProfile
        @($out) -contains $env:COMPUTERNAME | Should Be $false   # dispatcher dropped
        @($out) -contains 'FAR-HOST-SE'     | Should Be $true    # real target kept
    }
    It 'run-vulnerability drops the dispatcher (self-only) -> total=0, no fan-out status started' {
        $evts = New-Object System.Collections.ArrayList
        $emit = { param($e) [void]$evts.Add($e) }
        $res = & $mod {
            param($aid, $prm, $em)
            Invoke-JanetToolAction -ActionId $aid -Params $prm -Credential $null -Emit $em
        } 'run-vulnerability' @{ profileName = $SpecProfile; targets = $env:COMPUTERNAME; verifyOnly = $false } $emit
        [int]$res.summary.total | Should Be 0
        @($res.rows).Count      | Should Be 0
        $warn = @($evts | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and $_.text -match 'Self-guard' })
        $warn.Count | Should BeGreaterThan 0
        $started = @($evts | Where-Object { $_.type -eq 'status' -and $_.text -match "on \d+ host" })
        $started.Count | Should Be 0
    }
}

Describe 'ACAS 1.11.3 - the pool worker fails CLOSED when the engine source is not injected' {

    # Drive the real AcasUpdateWorker with an EMPTY $SpecFixSrcIn (8th arg) for the
    # NeedsSpecFix profile: it must return a fail-closed FAIL and take NO action (no
    # session, no host contact). An unreachable target proves we bailed on the guard first.
    It 'a NeedsSpecFix run with empty injected source returns FAIL (no write)' {
        $res = & $mod {
            param($sp)
            $tbl = $script:AcasUpdateProfiles
            # TargetIn, ProfileIn, Table, VerifyOnly=$false, Cred=$null, StageSource='', JavaFixSrc='', SpecFixSrc=''
            & $script:AcasUpdateWorker '0.0.0.0' $sp $tbl $false $null '' '' ''
        } $SpecProfile
        [string]$res | Should Match '^FAIL'
        [string]$res | Should Match 'fail-closed'
    }
    It 'the same run WITH a source present passes the source-guard (fails later only on unreachable target)' {
        $res = & $mod {
            param($sp)
            $tbl = $script:AcasUpdateProfiles
            & $script:AcasUpdateWorker '0.0.0.0' $sp $tbl $false $null '' '' $script:AcasSpecFixSrc
        } $SpecProfile
        # Source guard passed -> we proceed to the TCP probe and fail on unreachability,
        # NOT on the fail-closed source guard.
        [string]$res | Should Match 'unreachable'
        [string]$res | Should Not Match 'source not injected'
    }
}
