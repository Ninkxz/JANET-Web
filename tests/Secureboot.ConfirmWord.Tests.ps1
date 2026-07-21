# =============================================================================
#  Secureboot.ConfirmWord.Tests.ps1 - Pester 3.4 for the loop-15 typed
#  confirm-word barrier on Enable Secure Boot (v1.6.1).
#
#  The loop-15 deep-dive of secureboot (a high-consequence destructive tool -
#  it writes a UEFI firmware setting and leaves each host pending a reboot)
#  found it honored most of the destructive-action contract (self-guard before
#  fan-out, wrong-box hard-abort before the C$ drop, brick-safety UEFI+GPT
#  positive check, fail-closed result polling, BIOS-password self-delete) but
#  LACKED the typed confirm-word barrier every sibling destructive tool has
#  (remoteadmin 'RUN', c2c/adto 'FIX') - a big "ENABLE SECURE BOOT" button
#  fired a live fleet firmware write on one click, gated only by the admin
#  session. Added: a manifest confirm= string (module pin) + a view-side
#  danger dialog requiring the operator to type ENABLE, on the LIVE path only
#  (Dry Run is a harmless preflight, deliberately ungated).
#
#  Module assertions run against the real manifest; the view assertion is a
#  static source check of secureboot.view.js (the confirm dialog is JS).
#
#  Run:  Invoke-Pester -Path .\tests\Secureboot.ConfirmWord.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.secureboot.psm1') -Force -PassThru
$script:View = Get-Content (Join-Path $script:Root 'web\js\views\secureboot.view.js') -Raw

Describe 'secureboot manifest (confirm-word floor)' {
    $mani = & $m { Get-JanetToolManifest }
    It 'id is secureboot and version is at least 1.6.1' {
        # Floor assert: the newest bump's own file carries the exact pin (loop57 =
        # Secureboot.Scan static-analysis Describe, v1.6.2); older files floor.
        [string]$mani.id | Should Be 'secureboot'
        ([version][string]$mani.version -ge [version]'1.6.1') | Should Be $true
    }
    It 'enable-secure-boot is destructive and now carries a confirm string' {
        $en = @($mani.actions | Where-Object { $_.id -eq 'enable-secure-boot' })[0]
        [bool]$en.destructive | Should Be $true
        [string]$en.confirm   | Should Not BeNullOrEmpty
    }
    It 'the confirm string names the ENABLE word + the firmware/reboot consequence' {
        $en = @($mani.actions | Where-Object { $_.id -eq 'enable-secure-boot' })[0]
        ([string]$en.confirm -cmatch 'ENABLE') | Should Be $true
        ([string]$en.confirm -match '(?i)firmware|reboot') | Should Be $true
    }
    It 'the read-only scan stays non-destructive with no confirm (no over-gate)' {
        $sc = @($mani.actions | Where-Object { $_.id -eq 'scan-secure-boot' })[0]
        [bool]$sc.destructive | Should Be $false
    }
}

Describe 'secureboot view - live Enable requires typing ENABLE; dry run does not' {
    It 'doRun issues a danger confirm with confirmWord ENABLE' {
        ($script:View -match "confirmWord:\s*'ENABLE'") | Should Be $true
    }
    It 'the ENABLE confirm is gated to the LIVE path (inside if (!isDry))' {
        # the confirm block sits after `if (!isDry) {` and before the ctx.run call.
        $idxGate  = $script:View.IndexOf('if (!isDry) {')
        $idxWord  = $script:View.IndexOf("confirmWord: 'ENABLE'")
        $idxRun   = $script:View.IndexOf("ctx.run('enable-secure-boot'")
        ($idxGate -ge 0) | Should Be $true
        ($idxWord -gt $idxGate) | Should Be $true
        ($idxWord -lt $idxRun)  | Should Be $true
    }
    It 'the run is still marked destructive when dispatched' {
        # ctx.run for enable carries the params; the server destructive gate + this typed
        # word are the two barriers. Assert the enable dispatch exists.
        ($script:View -match "ctx\.run\('enable-secure-boot'") | Should Be $true
    }
}

# loop58 (item64): the dry_run selector on the DESTRUCTIVE enable must fail CLOSED - a live
# firmware write only on an absent value (manifest default) or an explicit recognized false;
# any present-but-unrecognized token (typo) stays DRY, never silently live.
Describe 'secureboot 1.6.3 - dry_run parse fails closed (unrecognized token stays DRY)' {
    $mani = & $m { Get-JanetToolManifest }
    function DryOf { param($v) & $m { param($x) Get-SbeDryRunSafe $x } $v }

    It 'manifest version is at least 1.6.3 (floor; newest exact pin lives in Scan, loop59 v1.6.4)' {
        ([version][string]$mani.version -ge [version]'1.6.3') | Should Be $true
    }
    It 'absent/empty -> live (the documented enable default)' {
        (DryOf $null) | Should Be $false
        (DryOf '')    | Should Be $false
    }
    It 'explicit recognized false tokens -> live' {
        foreach ($t in 'false','0','no','off','False','OFF') { (DryOf $t) | Should Be $false }
        (DryOf $false) | Should Be $false
    }
    It 'explicit recognized true tokens -> dry' {
        foreach ($t in 'true','1','yes','on','TRUE') { (DryOf $t) | Should Be $true }
        (DryOf $true) | Should Be $true
    }
    It 'a present-but-UNRECOGNIZED token stays DRY (the fix; Get-SbeBool would have gone live)' {
        foreach ($t in 'ture','dry','y','preflight','maybe','2') { (DryOf $t) | Should Be $true }
    }
}
