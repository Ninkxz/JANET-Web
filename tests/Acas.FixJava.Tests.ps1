# =============================================================================
#  Acas.FixJava.Tests.ps1 - Pester 3.4 for the ACAS Nemesis 1.11.0 Oracle-Java
#  REMOVE remediation, wired to the SHARED, vendor-gated Java engine
#  (modules\JanetWeb.javafix.psm1 - the ONE copy c2c's fix-java pillar and wpt's
#  fix-java action also call). No third fork.
#
#  PURE / offline unit scope - no real host, no WinRM, no msiexec. We assert:
#   (a) the acas manifest loads at 1.11.0;
#   (b) a new 'Oracle Java - Remove (fix-java)' profile exists, is flagged
#       NeedsJavaFix + ForbidSelf, and its Script calls Invoke-JanetJavaRemediation
#       (the SHARED engine, not a fork) - never a copy of the removal logic;
#   (c) the profile maps to the SAME Oracle-Java plugin set as the Software-Center
#       profile, as an ALTERNATE (Software Center stays the default Profiles[0]);
#   (d) the acas dispatch DROPS the dispatcher host BEFORE fan-out for the removal
#       path (self-guard: a Java uninstall can never hit the JANET box);
#   (e) the shared engine source is injected into the pool worker and the worker
#       fails CLOSED (a FAIL row, no action) when the source is empty/absent.
#
#  Run:  Invoke-Pester -Path .\tests\Acas.FixJava.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$jm  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.javafix.psm1') -Force -PassThru
$mod = Import-Module (Join-Path $script:Root 'modules\JanetWeb.acas.psm1')    -Force -PassThru

$RemoveProfile = 'Oracle Java - Remove (fix-java)'
$ScProfile     = 'Oracle Java - Software Center'

Describe 'ACAS 1.11.1 - manifest loads at the bumped version' {
    $manifest = & $mod { Get-JanetToolManifest }
    It 'manifest id is acas and version is at least 1.11.4' {
        [string]$manifest.id      | Should Be 'acas'
        # Floor assert (wpt-suite precedent 2026-07-16): exact pins in OLD test
        # files go stale on every bump; the newest bump's own test carries the
        # exact pin.
        ([version]$manifest.version -ge [version]'1.11.4') | Should Be $true
    }
}

Describe 'ACAS 1.11.0 - Oracle-Java REMOVE profile exists and uses the SHARED engine' {

    It 'the remove profile is registered in the App Update profile table' {
        $p = & $mod { param($n) $script:AcasUpdateProfiles[$n] } $RemoveProfile
        $p | Should Not BeNullOrEmpty
    }
    It 'the remove profile is flagged NeedsJavaFix + ForbidSelf (engine-injected, self-forbidden)' {
        $flags = & $mod {
            param($n)
            $p = $script:AcasUpdateProfiles[$n]
            [pscustomobject]@{ NeedsJavaFix = [bool]$p['NeedsJavaFix']; ForbidSelf = [bool]$p['ForbidSelf'] }
        } $RemoveProfile
        $flags.NeedsJavaFix | Should Be $true
        $flags.ForbidSelf   | Should Be $true
    }
    It 'its Script calls the SHARED Invoke-JanetJavaRemediation (not a forked copy of the removal logic)' {
        $txt = & $mod { param($n) $script:AcasUpdateProfiles[$n].Script.ToString() } $RemoveProfile
        $txt | Should Match 'Invoke-JanetJavaRemediation'
        # A fork would re-implement the msiexec /x + JavaSoft pruning here; it must NOT.
        $txt | Should Not Match 'msiexec'
        $txt | Should Not Match 'JavaSoft'
    }
    It 'the shared engine SOURCE is captured at module load for pool injection' {
        $len = & $mod { ($script:AcasJavaFixSrc).Length }
        [int]$len | Should BeGreaterThan 0
    }
    It 'the captured source defines the vendor-gated remediation (single source of truth)' {
        $src = & $jm { Get-JanetJavaFixSrc }
        $src | Should Match 'function Invoke-JanetJavaRemediation'
        $src | Should Match ([regex]::Escape('(?i)oracle|sun microsystems'))   # vendor gate
        $src | Should Match ([regex]::Escape('^\{[0-9A-Fa-f-]+\}$'))            # strict-GUID guard
    }
    It 'does NOT alter the existing Software-Center Java profile (removal is additive)' {
        $sc = & $mod { param($n) $script:AcasUpdateProfiles[$n] } $ScProfile
        $sc | Should Not BeNullOrEmpty
        $scTxt = & $mod { param($n) $script:AcasUpdateProfiles[$n].Script.ToString() } $ScProfile
        $scTxt | Should Match 'CCM_Application'          # still the SCCM install path
        $scTxt | Should Not Match 'Invoke-JanetJavaRemediation'
    }
}

Describe 'ACAS 1.11.0 - the removal profile maps to the SAME Java findings as an ALTERNATE' {

    It 'the Oracle-Java match rule offers Software Center (default) THEN the remove alternate' {
        $profiles = & $mod {
            @(Get-AcasProfileMatchTable | Where-Object { $_.Keywords -contains 'Oracle Java' })[0].Profiles
        }
        @($profiles)[0]           | Should Be $ScProfile        # default stays install-via-SC
        @($profiles) -contains $RemoveProfile | Should Be $true # removal is a selectable alternate
    }
    It 'an Oracle Java finding surfaces BOTH profiles (Patchable) so the operator can pick removal' {
        $g = & $mod {
            $f = @([pscustomobject]@{ Host='WS-1'; PluginId='1'; PluginName='Oracle Java SE Multiple Vulnerabilities'; Severity='High'; Cve='CVE-2024-0001'; Solution='' })
            @(Get-AcasVulnGroups -Findings $f)[0]
        }
        $g.Category                       | Should Be 'Patchable'
        @($g.ProfileNames)[0]             | Should Be $ScProfile
        @($g.ProfileNames) -contains $RemoveProfile | Should Be $true
    }
}

Describe 'ACAS 1.11.0 - self-guard DROPS the dispatcher before fan-out for the removal path' {

    It 'the remove profile is ForbidSelf; the Software-Center profile is not' {
        (& $mod { param($n) Get-AcasProfileForbidsSelf $n } $RemoveProfile) | Should Be $true
        (& $mod { param($n) Get-AcasProfileForbidsSelf $n } $ScProfile)     | Should Be $false
    }
    It 'Select-AcasNonSelfHosts strips THIS box from a removal wave, keeping foreign hosts' {
        $out = & $mod {
            param($n)
            @(Select-AcasNonSelfHosts -ProfileName $n -Hosts @($env:COMPUTERNAME, 'FAR-HOST-1') -Send { param($e) })
        } $RemoveProfile
        @($out) -contains $env:COMPUTERNAME | Should Be $false   # dispatcher dropped
        @($out) -contains 'FAR-HOST-1'      | Should Be $true    # real target kept
    }
    It 'a removal wave whose ONLY target is self is emptied before any job is built' {
        $out = & $mod {
            param($n)
            @(Select-AcasNonSelfHosts -ProfileName $n -Hosts @($env:COMPUTERNAME) -Send { param($e) })
        } $RemoveProfile
        @($out).Count | Should Be 0
    }
    It 'run-vulnerability drops the dispatcher (self-only) -> total=0, no fan-out status started' {
        $evts = New-Object System.Collections.ArrayList
        $emit = { param($e) [void]$evts.Add($e) }
        $res = & $mod {
            param($aid, $prm, $em)
            Invoke-JanetToolAction -ActionId $aid -Params $prm -Credential $null -Emit $em
        } 'run-vulnerability' @{ profileName = $RemoveProfile; targets = $env:COMPUTERNAME; verifyOnly = $false } $emit
        [int]$res.summary.total | Should Be 0
        @($res.rows).Count      | Should Be 0
        # Self-guard warning is emitted, and NO 'Update ... on N host(s)' status fan-out starts.
        $warn = @($evts | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and $_.text -match 'Self-guard' })
        $warn.Count | Should BeGreaterThan 0
        $started = @($evts | Where-Object { $_.type -eq 'status' -and $_.text -match "on \d+ host" })
        $started.Count | Should Be 0
    }
    It 'a NON-forbidding profile (Software Center) now ALSO drops self (1.11.1 broadened self-guard)' {
        # 1.11.1: Select-AcasNonSelfHosts drops the dispatcher for EVERY destructive
        # patch wave, not just ForbidSelf/Java-Remove. SC is still not ForbidSelf, but
        # the box is now dropped from its wave too (real target kept).
        $out = & $mod {
            param($n)
            @(Select-AcasNonSelfHosts -ProfileName $n -Hosts @($env:COMPUTERNAME, 'FAR-HOST-1') -Send { param($e) })
        } $ScProfile
        @($out) -contains $env:COMPUTERNAME | Should Be $false
        @($out) -contains 'FAR-HOST-1'      | Should Be $true
        @($out).Count | Should Be 1
    }
}

Describe 'ACAS 1.11.0 - the pool worker fails CLOSED when the engine source is not injected' {

    # Drive the real AcasUpdateWorker with an EMPTY $JavaFixSrcIn for the NeedsJavaFix
    # profile: it must return a fail-closed FAIL and take NO action (no session, no host
    # contact). An unreachable/empty target proves we bailed on the source-guard first.
    It 'a NeedsJavaFix run with empty injected source returns FAIL (no uninstall)' {
        $res = & $mod {
            param($rp)
            $tbl = $script:AcasUpdateProfiles
            # TargetIn, ProfileIn, Table, VerifyOnly=$false, Cred=$null, StageSource='', JavaFixSrc=''
            & $script:AcasUpdateWorker '0.0.0.0' $rp $tbl $false $null '' ''
        } $RemoveProfile
        [string]$res | Should Match '^FAIL'
        [string]$res | Should Match 'fail-closed'
    }
    It 'the same run WITH a source present passes the source-guard (fails later only on unreachable target)' {
        $res = & $mod {
            param($rp)
            $tbl = $script:AcasUpdateProfiles
            & $script:AcasUpdateWorker '0.0.0.0' $rp $tbl $false $null '' $script:AcasJavaFixSrc
        } $RemoveProfile
        # Source guard passed -> we proceed to the TCP probe and fail on unreachability,
        # NOT on the fail-closed source guard.
        [string]$res | Should Match 'unreachable'
        [string]$res | Should Not Match 'source not injected'
    }
}
