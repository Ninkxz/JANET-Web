# =============================================================================
#  WinUpgrade.CpuDiskVersionGates.Tests.ps1 - Pester 3.4 tests pinning the
#  readiness/target gates fixed in the 2026-07-24 audit of
#  JanetWeb.winupgrade.psm1 (v0.5.7). Every test here FAILS on the pre-audit code.
#
#    (1) SUPPORTED-CPU PATTERN. The pattern demanded a 5-digit Intel model number
#        ('i[3579]-1[1-4]\d{3}'), so every 4-digit 11th-13th gen MOBILE SKU
#        (i5-1135G7 / i7-1255U / i5-1335U - supported hardware, the bulk of the
#        laptop fleet) read as unsupported: HW INCOMPAT -> Blocked -> upgrade-drive
#        skipped it -> auto-fix wrote the MoSetup CPU/TPM bypass ON SUPPORTED
#        HARDWARE. The fix widens the model number to 4 OR 5 digits and MUST NOT
#        start accepting genuinely unsupported older parts, so both sides of the
#        boundary are asserted with real SKU strings.
#
#    (2) FREE-DISK GATE. $script:WinUpgradeMinDiskGB carried Windows 11's 64 GB
#        *total storage* minimum but is applied to FREE space, so a normally-loaded
#        workstation was permanently Blocked (disk) - while the module's own fix
#        text said "Free disk to 25+ GB". The gate is now the advertised 25 GB.
#
#    (3) DRIVE-PLAN BUILD GATE. Get-WinUpgradeDrivePlan - the pure authority the
#        UpgradeDrive worker mirrors - hardcoded 26100 while the worker gates on
#        $MinBuild, so it disagreed with the code it certifies on a 25H2 run.
#
#    (4) UNRECOGNISED TARGET VERSION. A version key the engine does not know used
#        to be silently rewritten to 24H2 - so a typo on upgrade-drive PINNED and
#        DROVE the target list toward a release nobody asked for. It is refused now.
#
#  Every test is PURE (helpers + the manifest) except the version-refusal ones,
#  which drive the REAL Invoke-JanetToolAction entry point: the refusal returns
#  BEFORE any runspace pool / dial, so no host is ever contacted (asserted).
#
#  Run:  Invoke-Pester -Path .\tests\WinUpgrade.CpuDiskVersionGates.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.winupgrade.psm1') -Force -PassThru

# Mirror of the supported-CPU test the diagnose / auto-fix remote blocks run inline
# (foreach pattern -> -match -> first hit wins). Evaluated INSIDE module scope so the
# pattern array never crosses the boundary and cannot unroll.
function Test-WinUpgradeCpuOk {
    param([string]$Name)
    [bool](& $m {
        param($n)
        $ok = $false
        foreach ($p in $script:WinUpgradeCpuPatterns) { if ($n -match $p) { $ok = $true; break } }
        $ok
    } $Name)
}

# Drive the REAL entry point in module scope, capturing every emitted event.
function Invoke-WinUpgradeAction {
    param([string]$ActionId, [hashtable]$Params)
    $script:vgEvents = New-Object System.Collections.ArrayList
    $emit = { param($e) [void]$script:vgEvents.Add($e) }
    $res = & $m {
        param($aid, $prm, $em)
        Invoke-JanetToolAction -ActionId $aid -Params $prm -Credential $null -Emit $em
    } $ActionId $Params $emit
    return @{ Result = $res; Events = @($script:vgEvents) }
}

Describe 'supported-CPU pattern accepts 4-digit Intel mobile SKUs (audit 2026-07-24)' {

    It 'i5-1135G7 (11th gen Tiger Lake mobile) is SUPPORTED' {
        Test-WinUpgradeCpuOk 'Intel(R) Core(TM) i5-1135G7 @ 2.40GHz' | Should Be $true
    }
    It 'i7-1185G7 (11th gen vPro mobile) is SUPPORTED' {
        Test-WinUpgradeCpuOk 'Intel(R) Core(TM) i7-1185G7 @ 3.00GHz' | Should Be $true
    }
    It 'i7-1255U (12th gen Alder Lake mobile) is SUPPORTED' {
        Test-WinUpgradeCpuOk 'Intel(R) Core(TM) i7-1255U' | Should Be $true
    }
    It 'i5-1335U (13th gen Raptor Lake mobile) is SUPPORTED' {
        Test-WinUpgradeCpuOk 'Intel(R) Core(TM) i5-1335U' | Should Be $true
    }
    It 'i5-1035G1 (10th gen Ice Lake mobile) is SUPPORTED' {
        Test-WinUpgradeCpuOk 'Intel(R) Core(TM) i5-1035G1 CPU @ 1.00GHz' | Should Be $true
    }

    # Regression: the 5-digit desktop/H forms that already worked must keep working.
    It 'i7-11700 (11th gen desktop, 5-digit) is still SUPPORTED' {
        Test-WinUpgradeCpuOk 'Intel(R) Core(TM) i7-11700 CPU @ 2.50GHz' | Should Be $true
    }
    It 'i5-10210U (10th gen, 5-digit) is still SUPPORTED' {
        Test-WinUpgradeCpuOk 'Intel(R) Core(TM) i5-10210U CPU @ 1.60GHz' | Should Be $true
    }
    It 'i5-13600K (13th gen desktop) is still SUPPORTED' {
        Test-WinUpgradeCpuOk 'Intel(R) Core(TM) i5-13600K' | Should Be $true
    }
    It 'i7-8650U (8th gen - the oldest supported Core family) is still SUPPORTED' {
        Test-WinUpgradeCpuOk 'Intel(R) Core(TM) i7-8650U CPU @ 1.90GHz' | Should Be $true
    }
    It 'Ryzen 5 5600X is still SUPPORTED (non-Intel branch untouched)' {
        Test-WinUpgradeCpuOk 'AMD Ryzen 5 5600X 6-Core Processor' | Should Be $true
    }

    # The other side of the boundary: widening the model number must NOT let a
    # genuinely unsupported pre-8th-gen part through. Those are 4-digit starting
    # 2-7, or 3-digit (1st gen) - neither can match 'i[3579]-1[0-4]...'.
    It 'i7-7700 (7th gen Kaby Lake) stays UNSUPPORTED' {
        Test-WinUpgradeCpuOk 'Intel(R) Core(TM) i7-7700 CPU @ 3.60GHz' | Should Be $false
    }
    It 'i5-6500 (6th gen Skylake) stays UNSUPPORTED' {
        Test-WinUpgradeCpuOk 'Intel(R) Core(TM) i5-6500 CPU @ 3.20GHz' | Should Be $false
    }
    It 'i7-6600U (6th gen mobile) stays UNSUPPORTED' {
        Test-WinUpgradeCpuOk 'Intel(R) Core(TM) i7-6600U CPU @ 2.60GHz' | Should Be $false
    }
    It 'i7-4790 (4th gen Haswell) stays UNSUPPORTED' {
        Test-WinUpgradeCpuOk 'Intel(R) Core(TM) i7-4790 CPU @ 3.60GHz' | Should Be $false
    }
    It 'i5-2400 (2nd gen Sandy Bridge) stays UNSUPPORTED' {
        Test-WinUpgradeCpuOk 'Intel(R) Core(TM) i5-2400 CPU @ 3.10GHz' | Should Be $false
    }
    It 'i5-750 (1st gen Lynnfield, 3-digit) stays UNSUPPORTED' {
        Test-WinUpgradeCpuOk 'Intel(R) Core(TM) i5 CPU 750 @ 2.67GHz' | Should Be $false
    }
    It 'Core 2 Duo E8400 stays UNSUPPORTED' {
        Test-WinUpgradeCpuOk 'Intel(R) Core(TM)2 Duo CPU E8400 @ 3.00GHz' | Should Be $false
    }
}

Describe 'free-disk gate is the advertised 25 GB, not the 64 GB total-storage minimum' {

    It 'the module constant is 25 GB free' {
        (& $m { $script:WinUpgradeMinDiskGB }) | Should Be 25
    }

    It 'the error-report helper defaults to a 25 GB free gate' {
        # 40 GB free is comfortably enough for a feature update, and was a permanent
        # DISK / BLOCK row (and a permanent "Blocked: disk") under the 64 GB gate.
        $rows = & $m { Get-WinUpgradeErrorRowSet -Build 22631 -MinBuild 26100 -FreeGB 40 }
        @($rows | Where-Object { $_.Category -eq 'DISK' }).Count | Should Be 0
        $rows.Count       | Should Be 1
        $rows[0].Category | Should Be 'NONE'
    }

    It 'a genuinely low disk (10 GB free) is STILL a DISK / BLOCK row' {
        $rows = & $m { Get-WinUpgradeErrorRowSet -Build 22631 -MinBuild 26100 -FreeGB 10 }
        $rows.Count       | Should Be 1
        $rows[0].Category | Should Be 'DISK'
        $rows[0].Severity | Should Be 'BLOCK'
        $rows[0].Evidence | Should Match '25\+ GB'
    }

    It 'the evidence text quotes the SAME number the fix text advises (no 64/25 split)' {
        $rows = & $m { Get-WinUpgradeErrorRowSet -Build 22631 -MinBuild 26100 -FreeGB 10 }
        $rows[0].Fix      | Should Match '25\+ GB'
        $rows[0].Evidence | Should Not Match '64'
    }
}

Describe 'Get-WinUpgradeDrivePlan gates on -MinBuild, not a hardcoded 26100' {

    It 'a 26100 box on a 25H2 (26200) run is NOT "already on target" - it is driven' {
        $p = & $m { Get-WinUpgradeDrivePlan -OsBuild 26100 -Eligible $true -MinBuild 26200 -Version '25H2' }
        $p.Skipped      | Should Be ''
        $p.WouldPin     | Should Be $true
        $p.WouldTrigger | Should Be $true
    }

    It 'a 26200 box on a 25H2 run IS skipped, and the skip text names the target version' {
        $p = & $m { Get-WinUpgradeDrivePlan -OsBuild 26200 -Eligible $true -MinBuild 26200 -Version '25H2' }
        $p.Skipped  | Should Be 'already 25H2+'
        $p.WouldPin | Should Be $false
    }

    It 'the defaults are unchanged (24H2 / 26100) so every existing caller behaves identically' {
        $p = & $m { Get-WinUpgradeDrivePlan -OsBuild 26100 -Eligible $true }
        $p.Skipped | Should Be 'already 24H2+'
    }
}

Describe 'an unrecognised target version is REFUSED, never silently substituted' {

    $out = Invoke-WinUpgradeAction -ActionId 'upgrade-drive' -Params @{ targets = 'WS-REMOTE-999'; product = 'Windows 11'; version = '24H3' }

    It 'upgrade-drive returns no rows and flags the bad version' {
        @($out.Result.rows).Count       | Should Be 0
        [int]$out.Result.summary.total  | Should Be 0
        [int]$out.Result.summary.badVersion | Should Be 1
    }
    It 'emits an ERROR naming the rejected version and the valid keys' {
        $err = $out.Events | Where-Object { $_.type -eq 'error' }
        $err | Should Not BeNullOrEmpty
        [string]$err.text | Should Match '24H3'
        [string]$err.text | Should Match '25H2'
    }
    It 'NEVER starts a dispatch (no runspace, no pin, no host contact)' {
        $starting = $out.Events | Where-Object { $_.type -eq 'status' -and $_.text -match 'Starting' }
        $starting | Should BeNullOrEmpty
        $rows = $out.Events | Where-Object { $_.type -eq 'row' }
        $rows | Should BeNullOrEmpty
    }
    It 'does NOT quietly log "defaulting to 24H2" any more' {
        $warn = $out.Events | Where-Object { $_.type -eq 'log' -and $_.text -match 'defaulting to 24H2' }
        $warn | Should BeNullOrEmpty
    }

    It 'the read-only version-gated ops refuse it too (auto-fix)' {
        $o2 = Invoke-WinUpgradeAction -ActionId 'auto-fix' -Params @{ targets = 'WS-REMOTE-999'; version = 'bogus' }
        @($o2.Result.rows).Count | Should Be 0
        ($o2.Events | Where-Object { $_.type -eq 'error' }) | Should Not BeNullOrEmpty
    }
    It 'a KNOWN version key still resolves (case-insensitive) - the refusal is not blanket' {
        (& $m { $script:WinUpgradeTargets.Contains('25H2') }) | Should Be $true
        (& $m { [int]$script:WinUpgradeTargets['25H2'].MinBuild }) | Should Be 26200
    }
}

Describe 'every destructive remote block carries the wrong-box abort (audit 2026-07-24)' {
    # Source-level assertions (the Winupgrade.RepairVerdict "inline mirror" idiom): these
    # blocks only ever execute on a REMOTE target, so behaviour cannot be unit-driven here -
    # what is pinned is that the guard is PRESENT in each one, since the pre-audit code had
    # it at the reboot step ALONE while the same blocks deleted drivers / $WINDOWS.~BT,
    # wrote policy, ran DISM+sfc and registered a SYSTEM task unguarded.
    $src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.winupgrade.psm1') -Raw

    It 'the AutoFix block aborts BEFORE the first fix, not just before the reboot' {
        # the abort returns the WRONG BOX shape, and it sits above the policy write
        $src | Should Match "Status='WRONG BOX'"
        $idxGuard  = $src.IndexOf("[FAIL] WRONG BOX: dialed")
        $idxPolicy = $src.IndexOf("# FIX policy: TRV=1 + Product + Info")
        ($idxGuard -gt 0)          | Should Be $true
        ($idxGuard -lt $idxPolicy) | Should Be $true
    }
    It 'the repair-health DISM and sfc blocks each guard themselves' {
        # (InstallCab's own pre-existing DNS-mismatch abort also says "DISM not run" - match
        # on the WRONG BOX phrasing so this pins the repair-health blocks specifically.)
        (@([regex]::Matches($src, 'WRONG BOX: dialed .*ABORTED, DISM not run')).Count) | Should Be 1
        (@([regex]::Matches($src, 'WRONG BOX: dialed .*ABORTED, sfc not run')).Count)  | Should Be 1
    }
    It 'the install-updates SYSTEM-task runner guards BEFORE Register-ScheduledTask' {
        $idxGuard = $src.IndexOf('return ''{"Status":"WrongBox","Nonce":"'' + $RunNonce')
        $idxReg   = $src.IndexOf('Register-ScheduledTask -TaskName "JANET_WUA"')
        ($idxGuard -gt 0)       | Should Be $true
        ($idxGuard -lt $idxReg) | Should Be $true
    }
    It 'the WMI/DCOM bootstrap guards too (it registers the same SYSTEM task)' {
        # audit 2026-07-25 (fable re-audit follow-up): the bootstrap is the shared
        # $script:WinUpgradeWuaBootstrapBlock now, so pin the ORDER inside that block -
        # identity check first, task registration after. (Behavioural coverage that it
        # mutates nothing on a mismatch lives in WinUpgrade.WrongBoxMutations.Tests.ps1.)
        $bs = [string](& $m { $script:WinUpgradeWuaBootstrapBlock })
        $idxGuard = $bs.IndexOf('$env:COMPUTERNAME.Trim().ToUpper() -ne')
        $idxReg   = $bs.IndexOf("Register-ScheduledTask -TaskName 'JANET_WUA'")
        ($idxGuard -gt 0)       | Should Be $true
        ($idxGuard -lt $idxReg) | Should Be $true
    }
    It 'a wrong-box abort is NOT booked as a success' {
        $src | Should Match "\`$r\.Ok = \(\[string\]\`$af\.Status -ne 'WRONG BOX'\)"
    }
}

Describe 'no-op remediations are audited Skipped, not VulnPatched Success' {
    $src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.winupgrade.psm1') -Raw

    It "the audit skip-set covers CLEAN / NO CHANGES / ALREADY ON TARGET" {
        $src | Should Match "\`$noOpStatuses = @\('DRY-RUN','Skipped','Cancelled','CLEAN','NO CHANGES','ALREADY ON TARGET'\)"
    }
    It 'DRIVEN / STAGED are deliberately NOT in the skip-set (they DID pin + trigger)' {
        $src | Should Not Match "'CLEAN','NO CHANGES','ALREADY ON TARGET','DRIVEN'"
    }
    It 'the repair watchdog exceeds the DISM+sfc runtime the tool advertises' {
        $src | Should Match "op -eq 'RepairHealth'\)   \{ \`$defThreads = 4;  \`$maxJobSeconds = 7200 \}"
    }
}

Describe 'manifest carries the audit version bump' {
    It 'version is 0.5.8' {
        # audit 2026-07-25 (fable re-audit follow-up): bumped for the wrong-box residual
        # pass (InstallCab staging + the WMI/DCOM bootstrap/cleanup guards).
        (& $m { (Get-JanetToolManifest).version }) | Should Be '0.5.8'
    }
}
