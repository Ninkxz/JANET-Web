# =============================================================================
#  WinUpgrade.SetupLogReadErrors.Tests.ps1 - an UNREADABLE setup log is never
#  reported as a clean one.
#
#  THE DEFECT (loop 2026-08-04): three places read
#  C:\$WINDOWS.~BT\Sources\Panther\setuperr.log and swallowed the failure, so an
#  ACL-denied or in-flight-locked log rendered as "nothing wrong":
#
#    error-report (:3240 -> :3295) - no DRIVER/signature rows were produced and,
#      with nothing else firing, the single confident row "No upgrade errors
#      detected" was emitted. On a host that failed with 0x8007000E that reads as
#      CLEAN and the operator never runs Set Page File.
#    diagnose (:2128) - the whole SETUP FAILURE ANALYSIS section rendered EMPTY and
#      the verdict computed as if the log were clean, with no hint the forensics
#      had been skipped.
#    auto-fix repair (:3131) - printed "[SKIP] No registry/CBS corruption signature
#      - repair not needed" and skipped the DISM/SFC repair on a host whose log
#      could not be read.
#
#  The module already had the honest precedent one action over: CheckUpgrade maps a
#  read failure to READERR -> Status FAILED (:1652/:1674). It simply was not swept
#  to the three siblings - the recurring failure mode in this repo.
#
#  These are SOURCE-SHAPE assertions on purpose: all three sites live inside remote
#  scriptblocks that are only reachable over a real WinRM session, so there is no
#  honest way to drive them locally without a shim harness this module does not
#  have. They pin the shape of the fix and, critically, that the confident
#  "no errors"/"not needed" verdicts can no longer be the sole outcome of a failed
#  read.
#
#  Run: Invoke-Pester -Path .\tests\WinUpgrade.SetupLogReadErrors.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Src  = Get-Content (Join-Path $script:Root 'modules\JanetWeb.winupgrade.psm1') -Raw

Describe 'error-report - an unreadable setuperr.log is its own row, not silence' {

    It 'the read failure is captured instead of being discarded' {
        # was: catch { $et='' }
        ($script:Src -match "catch \{ \`$et=''; \`$etErr=\`$_\.Exception\.Message \}") | Should Be $true
    }
    It 'a READ ERROR row is emitted' {
        ($script:Src -match "Category='READ ERROR'")                              | Should Be $true
        ($script:Src -match 'Could not read setuperr\.log - upgrade errors NOT analysed') | Should Be $true
    }
    It 'the NONE row still fires for a genuinely clean host (the fix did not overreach)' {
        ($script:Src -match "if \(\`$rows\.Count -eq 0\) \{ \[void\]\`$rows\.Add\(\[pscustomobject\]@\{ Category='NONE'") | Should Be $true
    }
}

# The first draft asserted the ordering by comparing IndexOf() positions in the source,
# and it FAILED - because it matched an entirely different site: the PURE helper
# Get-WinUpgradeErrorRowSet, which the worker's own comment says it "mirrors inline".
# That helper is called ONLY by tests, so it is the tested authority for this row set
# while the untested inline worker is the code that actually runs - precisely the
# structure that produces this repo's recurring drift. The fix therefore also went into
# the helper, and the ordering is now proven BEHAVIOURALLY against it instead of by
# counting characters.
Describe 'Get-WinUpgradeErrorRowSet (the tested authority) models the same rule' {
    $m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.winupgrade.psm1') -Force -PassThru

    It 'an unreadable log yields a READ ERROR row, never the NONE row' {
        $rows = @(& $m { Get-WinUpgradeErrorRowSet -Build 22631 -MinBuild 26100 -FreeGB 200 -SetupErrReadError 'Access is denied' })
        @($rows | Where-Object { $_.Category -eq 'READ ERROR' }).Count | Should Be 1
        @($rows | Where-Object { $_.Category -eq 'NONE' }).Count       | Should Be 0
    }
    It 'and it names the reason so the operator can act on it' {
        $rows = @(& $m { Get-WinUpgradeErrorRowSet -Build 22631 -MinBuild 26100 -FreeGB 200 -SetupErrReadError 'Access is denied' })
        ([string]$rows[0].Evidence) | Should Match '(?i)NOT analysed'
        ([string]$rows[0].Evidence) | Should Match '(?i)Access is denied'
    }
    It 'a genuinely clean host still gets exactly the NONE row (no overreach)' {
        $rows = @(& $m { Get-WinUpgradeErrorRowSet -Build 22631 -MinBuild 26100 -FreeGB 200 })
        @($rows).Count            | Should Be 1
        [string]$rows[0].Category | Should Be 'NONE'
    }
    It 'a read error does not suppress real findings - both are reported' {
        $rows = @(& $m { Get-WinUpgradeErrorRowSet -Build 22631 -MinBuild 26100 -FreeGB 10 -MinDisk 25 -SetupErrReadError 'locked' })
        @($rows | Where-Object { $_.Category -eq 'DISK' }).Count       | Should Be 1
        @($rows | Where-Object { $_.Category -eq 'READ ERROR' }).Count | Should Be 1
    }
    It 'a host already on the target build short-circuits before any of this' {
        $rows = @(& $m { Get-WinUpgradeErrorRowSet -Build 26100 -MinBuild 26100 -Version '24H2' -SetupErrReadError 'locked' })
        @($rows).Count            | Should Be 1
        [string]$rows[0].Category | Should Be 'NONE'
    }
}

Describe 'diagnose - a skipped forensic read says so' {
    It 'the read error is captured and initialised' {
        ($script:Src -match "\`$sr = \`$null; \`$curErrReadErr = ''")                  | Should Be $true
        ($script:Src -match "\`$curErrText = ''; \`$curErrReadErr = \`$_\.Exception\.Message") | Should Be $true
    }
    It 'and it prints a WARN that analysis was SKIPPED, not clean' {
        ($script:Src -match "setuperr\.log COULD NOT BE READ - setup failure analysis SKIPPED") | Should Be $true
    }
}

Describe 'auto-fix repair - an unreadable log does not read as "repair not needed"' {
    It 'the read error is captured' {
        ($script:Src -match "catch \{ \`$etReadErr=\`$_\.Exception\.Message \}") | Should Be $true
    }
    It 'it warns that corruption was NOT ruled out' {
        ($script:Src -match 'corruption NOT ruled out, repair NOT evaluated') | Should Be $true
    }
    # The sink matters as much as the message. $fixes books an applied fix -> Status=FIXED
    # -> audit VulnPatched/Success. A warning that a check could NOT be made must never
    # land there, or the fix for a false-clean would itself manufacture one. (The first
    # draft of this change wrote to a non-existent `$applied`, which would have been dead
    # code; it goes to $report.)
    It 'the warning goes to $report, never to $fixes' {
        ($script:Src -match "\[void\]\`$report\.Add\(""\[WARN\] setuperr\.log UNREADABLE") | Should Be $true
        ($script:Src -match "\`$fixes\.Add\('repair'\).*UNREADABLE")                        | Should Be $false
        ($script:Src -match "\`$applied \+=")                                               | Should Be $false
    }
}

Describe 'winupgrade - manifest EXACT pin (newest bump = 0.5.10, the setup-log read errors)' {
    # The exact pin lives with the newest bump's own tests; older files assert a floor.
    # Migrated here from Winupgrade.RepairVerdict.Tests.ps1, which now floors at 0.5.9.
    $m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.winupgrade.psm1') -Force -PassThru
    It 'winupgrade is exactly v0.5.10' {
        [string](& $m { (Get-JanetToolManifest).version }) | Should Be '0.5.10'
    }
}

Describe 'the honest precedent this was swept from is still intact' {
    It 'CheckUpgrade still maps a read failure to READERR -> FAILED' {
        ($script:Src -match "Code = 'READERR'")                        | Should Be $true
        ($script:Src -match "'READERR' \{ \`$r\.Status = 'FAILED'")     | Should Be $true
    }
}
