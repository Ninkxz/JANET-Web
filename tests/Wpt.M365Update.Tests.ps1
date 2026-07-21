# =============================================================================
#  Wpt.M365Update.Tests.ps1 - Pester 3.4 for the honest M365 Click-to-Run update
#  profiles (loop43, roadmap item40 M365 slice). The 'Microsoft 365 - Force Update'
#  and 'Microsoft 365 - Update (User Visible)' app-update profiles trigger
#  OfficeC2RClient.exe /update and then returned "OK (Office update triggered, exit
#  N)" - the exit code was interpolated into the string but NEVER tested, so a
#  NONZERO OfficeC2RClient exit (a real failure) read OK and, in app-update-apply,
#  booked a VulnPatched Success audit for a host whose Office was not updated. Now a
#  nonzero exit returns FAIL; exit 0 stays OK (accepted/started - the paired C2R
#  Verify, which gates on scenario success, confirms actual completion).
#
#  The profile Scripts run remotely (module-less), so this is static analysis of the
#  two profile blocks. Run:  Invoke-Pester -Path .\tests\Wpt.M365Update.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Force -PassThru
$script:Src  = Get-Content (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Raw

function Get-ProfileBlock {
    param([string]$Name)
    # from the profile's quoted key to the next top-level profile key (or Verify closing)
    ([regex]::Match($script:Src, "(?s)'" + [regex]::Escape($Name) + "'\s*=\s*@\{.*?Verify\s*=")).Value
}

Describe 'M365 Force Update profile - the OK is gated on the OfficeC2RClient exit code' {
    $blk = Get-ProfileBlock 'Microsoft 365 - Force Update'
    It 'the profile block was isolated' { ($blk.Length -gt 0) | Should Be $true }
    It 'it tests $proc.ExitCode -ne 0 and FAILs on nonzero (the false-clean fix)' {
        ($blk -match '\$proc\.ExitCode -ne 0.*FAIL') | Should Be $true
    }
    It 'the old unconditional "OK (...exit $($proc.ExitCode))" return is gone' {
        ($blk -match 'return "OK \(Office update triggered, exit \$\(\$proc\.ExitCode\)\)"') | Should Be $false
    }
}

Describe 'M365 User Visible profile - the OK is gated on the OfficeC2RClient exit code' {
    $blk = Get-ProfileBlock 'Microsoft 365 - Update (User Visible)'
    It 'the profile block was isolated' { ($blk.Length -gt 0) | Should Be $true }
    It 'it tests $proc.ExitCode -ne 0 and FAILs on nonzero' {
        ($blk -match '\$proc\.ExitCode -ne 0.*FAIL') | Should Be $true
    }
}

Describe 'wpt - both M365 profiles no longer interpolate an untested exit code into an OK' {
    It 'the unconditional OK-with-exit form appears nowhere in the module' {
        (@([regex]::Matches($script:Src, 'return "OK \(Office update triggered, exit \$\(\$proc\.ExitCode\)\)"')).Count) | Should Be 0
    }
}

Describe 'wpt - manifest exact version pin (newest bump = loop-43 M365 exit-code gate)' {
    It 'wpt is at v6.8.11' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        [string]$mani.version | Should Be '6.8.11'
    }
}
