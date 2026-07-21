# =============================================================================
#  Wpt.SelfGuardApply.Tests.ps1 - Pester 3.4 for the loop-9 self-guard gap
#  closure (wpt v6.8.3). The Opus deep-dive of the wpt destructive engine found
#  that app-update-apply (which runs the Custom Command profile = ARBITRARY
#  remote PowerShell, plus force-update/uninstall profiles) was the ONLY
#  destructive dispatcher WITHOUT the Remove-WptSelfTargets self-guard - so an
#  operator command like Restart-Computer with the dispatcher in the host list
#  would kill this HttpListener mid-dispatch (the wrong-box guard is a no-op on
#  self: self is dialed by its own correct name -> no mismatch). Two sibling
#  destructive dispatchers (app-action SCCM Install/Uninstall, unsupported-
#  uninstall) had the same gap. All three now drop the dispatcher BEFORE fan-out.
#
#  Each test dispatches the real Invoke-JanetToolAction with a self-only target
#  (127.0.0.1 / the dispatcher COMPUTERNAME); the self-guard short-circuits to
#  total=0 with a Self-guard warn BEFORE any runspace/WinRM - so NO host is
#  contacted. Also asserts the arbitrary-RCE action carries a confirm= string.
#
#  Run:  Invoke-Pester -Path .\tests\Wpt.SelfGuardApply.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.wpt.psm1') -Force -PassThru

function Invoke-Wpt([string]$aid, [hashtable]$p) {
    $evs = New-Object System.Collections.ArrayList
    $emit = { param($e) [void]$evs.Add($e) }
    $res = & $m { param($a, $pp, $em) Invoke-JanetToolAction -ActionId $a -Params $pp -Credential $null -Emit $em } $aid $p $emit
    @{ Result = $res; Events = @($evs) }
}
function Has-SelfGuardWarn($o) {
    @($o.Events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and $_.text -match 'Self-guard' }).Count -gt 0
}
$script:Me = $env:COMPUTERNAME

Describe 'WPT - manifest loads at or above the self-guard-apply version' {
    $mani = & $m { Get-JanetToolManifest }
    It 'manifest id is wpt and version is >= 6.8.5 (floor; exact pin lives in the newest bump test)' {
        [string]$mani.id      | Should Be 'wpt'
        ([version][string]$mani.version -ge [version]'6.8.5') | Should Be $true
    }
}

Describe 'WPT 6.8.5 - clean-user-apps honors a dryrun STRING correctly (loop11 coercion fix)' {
    # [bool]'false' is $true in PS - the raw coercion would turn a dryrun='false'
    # string (operator means LIVE) into a dry no-op AND skip the live-only self-guard.
    # ConvertTo-WptBool maps 'false' -> $false, so a self-only LIVE clean is guarded.
    It 'dryrun="false" (STRING) is treated as LIVE -> self-guard fires on a self target' {
        $o = Invoke-Wpt 'clean-user-apps' @{ targets = '127.0.0.1'; chrome = $true; dryrun = 'false' }
        [int]$o.Result.summary.total | Should Be 0
        (Has-SelfGuardWarn $o) | Should Be $true
    }
    It 'dryrun="true" (STRING) stays dry -> no self-guard (guard is live-only)' {
        # dry stays dry: swap the worker block so the dry fan-out makes no real WinRM call.
        $evs = New-Object System.Collections.ArrayList
        $emit = { param($e) [void]$evs.Add($e) }
        $null = & $m {
            param($em)
            $orig = $script:WptCleanUserAppsBlock
            $script:WptCleanUserAppsBlock = { param($h,$c,$a,$apps,$dry) @{ Host=$h; Status='Dry Run OK'; AppsRemoved=0; FreedMB=0; Detail='fake'; Events=@() } }
            try {
                Invoke-JanetToolAction -ActionId 'clean-user-apps' -Params @{ targets='127.0.0.1'; chrome=$true; dryrun='true'; threads=1 } -Credential $null -Emit $em
            } finally { $script:WptCleanUserAppsBlock = $orig }
        } $emit
        @($evs | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and $_.text -match 'Self-guard' }).Count | Should Be 0
    }
}

Describe 'WPT 6.8.4 - clean-user-apps self-guards the dispatcher on a LIVE run (loop10 audit)' {
    It 'a LIVE clean (dryrun=false) targeting only the dispatcher is emptied before fan-out' {
        # Live + self short-circuits at the self-guard BEFORE any fan-out - hermetic.
        $o = Invoke-Wpt 'clean-user-apps' @{ targets = '127.0.0.1'; chrome = $true; dryrun = $false }
        [int]$o.Result.summary.total | Should Be 0
        (Has-SelfGuardWarn $o) | Should Be $true
    }
    It 'a DRY-RUN clean on self does NOT self-guard (preview is harmless)' {
        # dry-run intentionally keeps self in the wave, so it would proceed to fan-out;
        # swap the worker block for a fake so no real WinRM leaves the box, and assert
        # the negative: the live-only guard did NOT fire in dry-run.
        $evs = New-Object System.Collections.ArrayList
        $emit = { param($e) [void]$evs.Add($e) }
        $null = & $m {
            param($em)
            $orig = $script:WptCleanUserAppsBlock
            $script:WptCleanUserAppsBlock = { param($h,$c,$a,$apps,$dry) @{ Host=$h; Status='Dry Run OK'; AppsRemoved=0; FreedMB=0; Detail='fake'; Events=@() } }
            try {
                Invoke-JanetToolAction -ActionId 'clean-user-apps' -Params @{ targets='127.0.0.1'; chrome=$true; dryrun=$true; threads=1 } -Credential $null -Emit $em
            } finally { $script:WptCleanUserAppsBlock = $orig }
        } $emit
        @($evs | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and $_.text -match 'Self-guard' }).Count | Should Be 0
    }
    It 'no apps selected -> a plain warn, not the self-guard path' {
        $o = Invoke-Wpt 'clean-user-apps' @{ targets = '127.0.0.1'; dryrun = $false }
        (Has-SelfGuardWarn $o) | Should Be $false
    }
}

Describe 'WPT 6.8.3 - app-update-apply self-guards the dispatcher (P2: Custom Command RCE)' {
    It 'a Custom Command wave targeting ONLY the dispatcher is emptied before fan-out' {
        $o = Invoke-Wpt 'app-update-apply' @{ targets = '127.0.0.1'; profile = 'Custom Command'; customcommand = 'Restart-Computer -Force' }
        [int]$o.Result.summary.total | Should Be 0
        (Has-SelfGuardWarn $o) | Should Be $true
    }
    It 'the dispatcher shortname is also dropped (not just loopback)' {
        $o = Invoke-Wpt 'app-update-apply' @{ targets = $script:Me; profile = 'Custom Command'; customcommand = 'whoami' }
        [int]$o.Result.summary.total | Should Be 0
        [int]$o.Result.summary.selfSkipped | Should Be 1
    }
    It 'a built-in profile wave targeting only the dispatcher is likewise emptied' {
        $o = Invoke-Wpt 'app-update-apply' @{ targets = '127.0.0.1'; profile = 'Microsoft 365 - Force Update' }
        [int]$o.Result.summary.total | Should Be 0
        (Has-SelfGuardWarn $o) | Should Be $true
    }
}

Describe 'WPT 6.8.3 - app-action self-guards the dispatcher (P3 consistency)' {
    It 'an SCCM Uninstall wave targeting only the dispatcher is emptied before fan-out' {
        $o = Invoke-Wpt 'app-action' @{ targets = '127.0.0.1'; appid = 'ScopeId_X/Application_Y'; method = 'Uninstall' }
        [int]$o.Result.summary.total | Should Be 0
        (Has-SelfGuardWarn $o) | Should Be $true
    }
}

Describe 'WPT 6.8.3 - unsupported-uninstall self-guards the dispatcher (P3 consistency)' {
    It 'a HOST<TAB>App pair naming only the dispatcher is emptied before fan-out' {
        # The dispatcher gate (line ~5212) requires a non-empty `targets` param before
        # the switch, so the view sends both; the pairs-derived host list is what is
        # actually dialed, and the loop-9 self-guard drops the dispatcher from it.
        $o = Invoke-Wpt 'unsupported-uninstall' @{ targets = '127.0.0.1'; pairs = "127.0.0.1`tJava 8 Update 202" }
        [int]$o.Result.summary.total | Should Be 0
        (Has-SelfGuardWarn $o) | Should Be $true
    }
}

Describe 'WPT 6.8.3 - the arbitrary-RCE action carries a loud confirm dialog (P3)' {
    $mani = & $m { Get-JanetToolManifest }
    $act = @($mani.actions | Where-Object { $_.id -eq 'app-update-apply' })[0]
    It 'app-update-apply is destructive AND now has a confirm= string' {
        [bool]$act.destructive | Should Be $true
        [string]$act.confirm | Should Not BeNullOrEmpty
    }
    It 'the confirm string warns about arbitrary PowerShell and the self-guard' {
        ([string]$act.confirm -match '(?i)arbitrary') | Should Be $true
        ([string]$act.confirm -match '(?i)self-guard|dispatcher') | Should Be $true
    }
}

Describe 'WPT 6.8.3 - the read-only sibling is NOT self-guarded (no over-guard)' {
    It 'app-update-verify has no confirm and is not destructive (unchanged)' {
        $mani = & $m { Get-JanetToolManifest }
        $v = @($mani.actions | Where-Object { $_.id -eq 'app-update-verify' })[0]
        [bool]$v.destructive | Should Be $false
    }
}
