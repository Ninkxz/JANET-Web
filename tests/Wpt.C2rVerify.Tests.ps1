# =============================================================================
#  Wpt.C2rVerify.Tests.ps1 - Pester 3.4 for the honest M365 Click-to-Run verify
#  verdict (loop24, roadmap item 15). The M365 "Force Update" / "User Visible"
#  profiles decide "Verified" from the ClickToRun\Configuration registry key.
#  The old rule used ONLY the key's LastWriteTime freshness (<7 days), but C2R
#  bumps that key on EVERY update attempt INCLUDING failures - so a failed Force
#  Update read Verified=$true with the OLD, still-vulnerable version (a false-
#  clean). Now Verified is TRUE only when the key is fresh AND the last update
#  scenario SUCCEEDED (LastScenarioResult), $null when unknown (never over-claims).
#
#  Get-WptC2rVerified is the canonical verdict; the M365C2RVerify scriptblock
#  mirrors it inline (it runs remotely via Invoke-Command, can't call a module fn).
#
#  Pure function, no I/O. Run:  Invoke-Pester -Path .\tests\Wpt.C2rVerify.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Force -PassThru

function Get-Verdict {
    param([bool]$HasTs, [double]$Age, [string]$Result)
    (& $script:Mod { param($h, $a, $r) Get-WptC2rVerified -HasTimestamp $h -AgeDays $a -ScenarioResult $r } $HasTs $Age $Result)
}

Describe 'Get-WptC2rVerified - fresh + succeeded is the ONLY green' {
    It 'no timestamp -> $null (unknown)' {
        Get-Verdict $false 0 'Success' | Should Be $null
    }
    It 'stale key (>= 7 days) -> $false, even if the scenario says Success' {
        Get-Verdict $true 10 'Success' | Should Be $false
    }
    It 'fresh + LastScenarioResult Success -> $true' {
        Get-Verdict $true 2 'Success' | Should Be $true
    }
    It 'fresh but the last scenario FAILED -> $false (the false-clean fix)' {
        Get-Verdict $true 2 'Failure' | Should Be $false
    }
    It 'fresh but the scenario result is unknown/blank -> $null (never over-claims)' {
        Get-Verdict $true 2 '' | Should Be $null
    }
    It 'SuccessRebootRequired still counts as success' {
        Get-Verdict $true 2 'SuccessRebootRequired' | Should Be $true
    }
    It 'the success match is case-insensitive' {
        Get-Verdict $true 2 'success' | Should Be $true
    }
}

Describe 'wpt M365 C2R verify scriptblock - gates on the scenario result, not just mtime' {
    $moduleSrc = Get-Content (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Raw
    It 'the M365 verify reads LastScenarioResult' {
        ($moduleSrc -match 'LastScenarioResult') | Should Be $true
    }
}

Describe 'wpt - manifest version floor (honest C2R verify shipped in 6.8.8; exact pin migrated to newest bump)' {
    It 'wpt is at or past v6.8.8' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        ([version][string]$mani.version -ge [version]'6.8.8') | Should Be $true
    }
}

# loop87: the Chrome/Edge updater verify (New-WptUpdateClientVerify) had the SAME mtime-only false-clean the
# C2R verify above once had - a fresh Clients\{GUID} key read Verified=$true even with an OLD version after a
# failed/no-op update. Now it also reads the sibling ClientState\{GUID}\LastInstallerResult (0 = last install
# SUCCEEDED) and is fresh-AND-succeeded, byte-identical to acas Get-AcasClientVerified (proven behaviorally in
# Acas.ClientVerify.Tests.ps1). Static assertion on the generated remote scriptblock body.
Describe 'wpt Chrome/Edge verify scriptblock - gates on the install result, not just mtime (loop87)' {
    $moduleSrc = Get-Content (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Raw
    It 'the generated verify reads the sibling ClientState (LastCheckSuccess freshness + LastInstallerResult gate)' {
        ($moduleSrc -match "\`$csp = \`$p -replace '\\\\Clients\\\\', '\\ClientState\\'") | Should Be $true
        ($moduleSrc -match '\$cs\.LastCheckSuccess')                                      | Should Be $true
        ($moduleSrc -match '\$cs\.LastInstallerResult')                                   | Should Be $true
    }
    It 'the DEAD Get-Item .LastWriteTime read is GONE from New-WptUpdateClientVerify (loop88 - it was always null -> inert)' {
        $fn = [regex]::Match($moduleSrc, '(?s)function New-WptUpdateClientVerify.*?\[scriptblock\]::Create').Value
        ($fn -match '\$mod = \$key\.LastWriteTime')                                                       | Should Be $false
        ($fn -match '\$verified = if \(\$mod\) \{ \(\(Get-Date\) - \$mod\)\.TotalDays -lt 14 \}')          | Should Be $false
    }
    It 'the fresh-AND-success gate is present' {
        ($moduleSrc -match '\(\(Get-Date\) - \$mod\)\.TotalDays -ge 14') | Should Be $true
        ($moduleSrc -match '\[bool\]\(\$lastResult -eq 0\)')            | Should Be $true
    }
    It 'wpt manifest is at or past 6.8.17 (client-verify real-timestamp fix; exact pin migrated to newest bump)' {
        ([version][string](& $script:Mod { (Get-JanetToolManifest).version }) -ge [version]'6.8.17') | Should Be $true
    }
}

# audit 2026-07-28: the loop88 test above scoped its assertion to ONE function AND to one
# exact spelling, so three further live instances of the same defect survived it - the M365
# C2R verify, the Oracle Java verify and Health Scan's reboot-age probe. Get-Item on a
# REGISTRY key returns a RegistryKey, which has NO .LastWriteTime member: the read yields
# $null silently and whatever it feeds becomes permanently inert. This Describe is
# deliberately MODULE-WIDE and spelling-agnostic so a fourth instance cannot slip through.
Describe 'wpt - no probe takes a timestamp from a REGISTRY key (module-wide, audit 2026-07-28)' {
    $moduleSrc = Get-Content (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Raw
    $lines = Get-Content (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1')

    It 'no Get-Item on an HKLM:/HKCU: path is bound to a variable whose .LastWriteTime is then read' {
        # Collect every variable assigned from a Get-Item over a registry path, then assert
        # none of them is later dereferenced for .LastWriteTime anywhere in the file.
        $regVars = @()
        foreach ($ln in $lines) {
            $mm = [regex]::Matches($ln, '\$(\w+)\s*=\s*(?:if \([^)]*\) \{ )?Get-Item\b[^\r\n]*?(HK(?:LM|CU|CR|U|CC)):')
            foreach ($x in $mm) { $regVars += $x.Groups[1].Value }
        }
        $offenders = @()
        foreach ($v in ($regVars | Select-Object -Unique)) {
            if ($moduleSrc -match ("\`$$v\.LastWriteTime")) { $offenders += $v }
        }
        ($offenders -join ', ') | Should Be ''
    }

    It 'the M365 C2R verify takes its timestamp from the real UpdateDetectionLastRunTime value' {
        $sb = [regex]::Match($moduleSrc, '(?s)\$script:M365C2RVerify = \{.*?\r?\n\}').Value
        ($sb -match 'UpdateDetectionLastRunTime')    | Should Be $true
        ($sb -match '\$key\.LastWriteTime')          | Should Be $false
    }

    It 'the Oracle Java verify takes its timestamp from the jvm.dll FILE, not the JavaSoft key' {
        ($moduleSrc -match '\$skey\.LastWriteTime')  | Should Be $false
        ($moduleSrc -match '\$jf = Get-Item -LiteralPath \$jvm') | Should Be $true
        ($moduleSrc -match '\$mod = \$jf\.LastWriteTime')        | Should Be $true
    }

    It 'Health Scan no longer fabricates a <1d reboot age when it has no datable mark' {
        ($moduleSrc -match "\{ '<1d' \}") | Should Be $false
        ($moduleSrc -match 'pending\.xml') | Should Be $true
    }

    It 'wpt manifest is at or past 6.10.4 (floor; exact pin migrated to the newest bump test)' {
        ([version][string](& $script:Mod { (Get-JanetToolManifest).version }) -ge [version]'6.10.4') | Should Be $true
    }
}

# audit 2026-07-28 (cross-fork drift slice): same defect as acas, and here it is a
# SAME-FILE asymmetry - the correct verify-and-clean pattern (remove the orphaned
# Uninstall key across all three hives, then re-verify) already lives in this module's
# Remove App path, and the MSXML profile never received it. Reclassified rather than
# made to delete, per that same tail's rule that the key may only go once the product's
# FILES are confirmed gone; this profile has no InstallLocation to prove that.
Describe 'wpt 6.10.5 - MSXML 1605 is an honest error, not a phantom removal' {
    $moduleSrc = Get-Content (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Raw

    It '1605 is no longer bucketed with the successes' {
        ($moduleSrc -match '\$proc\.ExitCode -in 0,1605,3010') | Should Be $false
        ($moduleSrc -match '\$proc\.ExitCode -in 0,3010')      | Should Be $true
    }
    It '1605 routes to $errors and says nothing was uninstalled' {
        ($moduleSrc -match "elseif \(\`$proc\.ExitCode -eq 1605\)")   | Should Be $true
        ($moduleSrc -match 'MSI does not know this product \(1605\)') | Should Be $true
    }
    It 'PARTIAL is left alone - this fork drains on -like OK*, so PARTIAL already fails' {
        # pins the reason the desktop twin needed FAIL and this one does not, so the
        # desktop change is not "ported back" and made into a no-op regression.
        ($moduleSrc -match "PARTIAL \(\`$summary")        | Should Be $true
        ($moduleSrc -match "\`"\`$result\`" -like 'OK\*'") | Should Be $true
    }
    It 'the correct clean-the-key pattern still exists on the Remove App path' {
        ($moduleSrc -match 'remove the orphaned uninstall registry key from all three hives') | Should Be $true
    }
    It 'wpt manifest is exactly 6.10.5 (audit 2026-07-28 MSXML 1605)' {
        [string](& $script:Mod { (Get-JanetToolManifest).version }) | Should Be '6.10.5'
    }
}
