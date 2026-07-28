# =============================================================================
#  Winupgrade.RepairVerdict.Tests.ps1 - Pester 3.4 for the component-store repair
#  verdict (Get-WinUpgradeRepairVerdict, loop37 / winupgrade deep-dive F7, item 31).
#  The repair-health / AutoFix DISM+SFC verdict classifies the sfc /scannow output
#  into no-violations / repaired / could-not-fix / blocked. The final else branch
#  defaulted UNPARSEABLE sfc text (a localized OS, a truncated capture) to
#  'no violations', which then read as a CLEAN component store - a fail-open: the
#  operator sees CLEAN while the repair status is actually unknown. Now an
#  unmatched sfc reads 'unknown' and the verdict is PARTIAL (not confirmed clean),
#  never CLEAN.
#
#  Get-WinUpgradeRepairVerdict is a pure helper (the AutoFix worker mirrors it
#  inline). Run:  Invoke-Pester -Path .\tests\Winupgrade.RepairVerdict.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.winupgrade.psm1') -Force -PassThru

function Get-Verdict {
    param($DismExit, [string]$SfcText, [bool]$DismError = $false, [bool]$SfcError = $false)
    (& $script:Mod { param($dx, $st, $de, $se) Get-WinUpgradeRepairVerdict -DismExit $dx -SfcText $st -DismError $de -SfcError $se } $DismExit $SfcText $DismError $SfcError)
}

Describe 'Get-WinUpgradeRepairVerdict - an UNPARSEABLE sfc no longer reads CLEAN (F7 fail-open)' {
    It 'gibberish / localized sfc output -> sfc unknown, status PARTIAL (not CLEAN)' {
        $v = Get-Verdict -DismExit 0 -SfcText 'Windows-Ressourcenschutz hat keine ...'
        $v.Sfc    | Should Be 'unknown'
        $v.Status | Should Be 'PARTIAL'
    }
    It 'empty sfc output -> unknown / PARTIAL, never CLEAN' {
        $v = Get-Verdict -DismExit 0 -SfcText ''
        $v.Status | Should Not Be 'CLEAN'
    }
}

Describe 'Get-WinUpgradeRepairVerdict - the known outcomes are unchanged' {
    It 'no-violations sfc + dism ok -> CLEAN' {
        (Get-Verdict -DismExit 0 -SfcText 'Windows Resource Protection did not find any integrity violations.').Status | Should Be 'CLEAN'
    }
    It 'successfully repaired -> REPAIRED' {
        (Get-Verdict -DismExit 0 -SfcText 'Windows Resource Protection found corrupt files and successfully repaired them.').Status | Should Be 'REPAIRED'
    }
    It 'unable to fix -> PARTIAL' {
        (Get-Verdict -DismExit 0 -SfcText 'Windows Resource Protection found corrupt files but was unable to fix some of them.').Status | Should Be 'PARTIAL'
    }
    It 'a DISM error -> FAILED' {
        (Get-Verdict -DismExit 1 -SfcText 'did not find any integrity violations').Status | Should Be 'FAILED'
    }
}

Describe 'winupgrade AutoFix - the inline verdict mirror also treats unknown sfc as not-clean' {
    $src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.winupgrade.psm1') -Raw
    It 'the module carries the unknown-sfc handling (helper + mirror)' {
        (@([regex]::Matches($src, "'unknown'")).Count -ge 2) | Should Be $true
    }
}

# audit 2026-07-28: AutoFix booked each of its three fixes into $fixes BEFORE attempting the
# operation, and no failure arm took the marker back. $status is `elseif ($fixes.Count -gt 0)
# { 'FIXED' }`, and 'FIXED' is not in $noOpStatuses - so a host where DISM exited non-zero, sfc
# errored AND the $WINDOWS.~BT delete was denied still reported Status=FIXED, Detail="Applied:
# repair; staging-cleared", and audited VulnPatched/Success/itemCount=1. repair-health in this
# same module already mapped a non-zero DISM to FAILED; AutoFix was the odd one out.
Describe 'winupgrade 0.5.9 - AutoFix books a fix only AFTER it actually succeeded' {
    $src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.winupgrade.psm1') -Raw

    It "'repair' is gated behind a success flag, not added up front" {
        ($src -match '\$repairOk=\$false')                    | Should Be $true
        ($src -match 'if \(\$repairOk\) \{ \[void\]\$fixes\.Add\(''repair''\) \}') | Should Be $true
    }
    It "'staging-cleared' is booked inside the try, after a successful Remove-Item" {
        # the Add must follow Remove-Item on the same live-run line, not precede the try
        ($src -match "Remove-Item -LiteralPath \`$btPath -Recurse -Force -ErrorAction Stop; \[void\]\`$fixes\.Add\('staging-cleared'\)") | Should Be $true
    }
    It 'the expired-pause clear no longer sets $clearedAny before a SilentlyContinue delete' {
        # the End value must now be removed with -ErrorAction Stop inside a try, and
        # $clearedAny must be set only on the success path
        ($src -match 'Remove-ItemProperty -Path \$wuUx -Name \$pair\.End -ErrorAction Stop') | Should Be $true
        ($src -match '\$clearedAny=\$true; \[void\]\$report\.Add\("\[FIX\] Cleared EXPIRED pause') | Should Be $true
    }
    It 'a run where every fix failed therefore books NO CHANGES, which audits Skipped' {
        # NO CHANGES is the else arm of the same $status expression and is in $noOpStatuses
        ($src -match "else \{ 'NO CHANGES' \}")   | Should Be $true
        ($src -match "'NO CHANGES'")               | Should Be $true
    }
}

Describe 'winupgrade - manifest exact version pin (newest bump = audit 2026-07-28 AutoFix honest FIXED)' {
    It 'winupgrade is at v0.5.9' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        [string]$mani.version | Should Be '0.5.9'
    }
}
