# =============================================================================
#  C2c.PillarTargets.Tests.ps1 - Pester 3.4 tests for the v1.10.0 import-scoped
#  targeting rework: per-pillar remediation and run-all dial ONLY the hosts the
#  imported Tanium "C2C Compliance Status" CSV flagged for each pillar - NEVER the
#  whole target list. The server re-derives the pillar host-sets from the CSV every
#  call (nothing persists) and the operator's checked hosts are an ALLOW-LIST
#  intersected against that set, never the dispatch list.
#
#  No WinRM call ever leaves this box: the per-host worker ($script:C2cFixBlock) is
#  swapped for a self-contained ECHO shim that returns the pillar set + host it was
#  dialed with (Detail 'PILLARS=a+b'), so the runspace fan-out runs locally and each
#  dialed host row proves exactly what was dispatched. Refusal cases short-circuit
#  before any fan-out (no shim needed, but it is harmless).
#
#  Run:  Invoke-Pester -Path .\tests\C2c.PillarTargets.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$cm = Import-Module (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1') -Force -PassThru

function New-C2cTempCsv {
    param([string]$Content)
    $p = Join-Path ([System.IO.Path]::GetTempPath()) ("c2c_pt_{0}.csv" -f ([guid]::NewGuid().ToString('N')))
    Set-Content -LiteralPath $p -Value $Content -Encoding UTF8
    return $p
}

# Run a fix action (per-pillar or run-all) with the per-host worker swapped for an
# ECHO shim that reports the EXACT pillar set each host was dialed with.
function Invoke-C2cFix {
    param([string]$ActionId, [hashtable]$Params, [bool]$Shim = $true)
    $script:__rows = New-Object System.Collections.ArrayList
    $script:__logs = New-Object System.Collections.ArrayList
    $emit = {
        param($e)
        if     ($e -and $e.type -eq 'row') { [void]$script:__rows.Add($e) }
        elseif ($e -and $e.type -eq 'log') { [void]$script:__logs.Add($e) }
    }
    if ($Shim) {
        & $cm {
            $script:__origFixBlock = $script:C2cFixBlock
            $script:C2cFixBlock = {
                param([string]$Computer, $Cred, [string]$Auth, [bool]$AttemptOffline, [string[]]$Pillars, [bool]$DoEnable, [string]$TaniumService, [string]$TaniumInstalledSrc, [string]$BundleJson, [bool]$WinrmHeal, [string]$WinrmHealSrc)
                $ps = @(@($Pillars) | ForEach-Object { [string]$_ })
                @{ Host = $Computer; Ping = 'shim'; Status = 'FIXED'; Detail = ('PILLARS=' + ($ps -join '+'));
                   Report = ''; Pillars = @($ps | ForEach-Object { [pscustomobject]@{ Name = $_; Action = 'shim'; Result = 'FIXED'; Detail = 'shim' } }) }
            }
        }
    }
    try {
        $res = Invoke-JanetToolAction -ActionId $ActionId -Params $Params -Credential $null -Emit $emit
    } finally {
        if ($Shim) { & $cm { $script:C2cFixBlock = $script:__origFixBlock; Remove-Variable -Name __origFixBlock -Scope Script -ErrorAction SilentlyContinue } }
    }
    [pscustomobject]@{ Result = $res; Rows = @($script:__rows); Logs = @($script:__logs) }
}

# -----------------------------------------------------------------------------
Describe 'C2C per-pillar target resolution - dial ONLY the import-flagged hosts, narrowed to the checked subset' {

    # HOSTP fails Patches (fixable HERE). HOSTX is in the CSV but fails Host Firewall
    # ONLY (so it is NOT flagged for Patches). HOSTZ is not in the CSV at all.
    $csvBody = @"
C2C Compliance Status:Compliance,C2C Compliance Status:Date,C2C Compliance Status:Age (Bucketed),Computer Name,Count
"Non-Compliant
Failed Rule 5 - Patching",,,HOSTP.area52.afnoapps.usaf.mil,1
"Non-Compliant
Failed Rule 2 - Host Firewall",,,HOSTX.area52.afnoapps.usaf.mil,1
"@
    $csv = New-C2cTempCsv $csvBody
    # Operator checks all three; only HOSTP is Patches-flagged.
    $out = Invoke-C2cFix -ActionId 'fix-patches' -Params @{ targets = "HOSTP`nHOSTX`nHOSTZ"; csvPath = $csv; confirm = 'FIX'; attemptOffline = $true; threads = 4 }

    It '(a) dials the host FLAGGED for Patches with ONLY the Patches pillar' {
        $p = @($out.Rows | Where-Object { $_.Host -eq 'HOSTP' -and $_.Status -eq 'FIXED' })[0]
        $p | Should Not BeNullOrEmpty
        $p.Detail | Should Be 'PILLARS=Patches'
    }

    It '(a) dials EXACTLY one host (only the import-flagged one), never the whole target list' {
        @($out.Rows | Where-Object { $_.Status -eq 'FIXED' }).Count | Should Be 1
    }

    It '(b) DROPS a host that is in the CSV but NOT flagged for Patches (never dialed) + warns' {
        @($out.Rows | Where-Object { $_.Host -eq 'HOSTX' -and $_.Status -eq 'FIXED' }).Count | Should Be 0
        @($out.Logs | Where-Object { $_.level -eq 'warn' -and $_.text -match 'HOSTX' }).Count | Should Not Be 0
    }

    It '(c) DROPS a host absent from the CSV entirely (never dialed) + warns' {
        @($out.Rows | Where-Object { $_.Host -eq 'HOSTZ' -and $_.Status -eq 'FIXED' }).Count | Should Be 0
        @($out.Logs | Where-Object { $_.level -eq 'warn' -and $_.text -match 'HOSTZ' }).Count | Should Not Be 0
    }

    Remove-Item -LiteralPath $csv -Force -ErrorAction SilentlyContinue
}

# -----------------------------------------------------------------------------
Describe 'C2C per-pillar fix - MANUAL mode (no import) dials EXACTLY the typed hosts' {

    # v1.12.0 dual-mode: with NO csvPath there is no import to scope against, so the fix
    # dials exactly the typed Target Computers for the chosen pillar (the operator owns the
    # list) - it is NOT rejected. Every other guard (confirm word, self-guard) still applies.
    $out = Invoke-C2cFix -ActionId 'fix-patches' -Params @{ targets = "HOSTP`nHOSTZ"; confirm = 'FIX'; attemptOffline = $true; threads = 4 }

    It 'with targets but NO csvPath -> MANUAL mode: dials the typed host(s), NOT rejected' {
        $out.Result.summary.rejected | Should Not Be $true
        @($out.Rows | Where-Object { $_.Status -eq 'FIXED' }).Count | Should Be 2
        (@($out.Rows | Where-Object { $_.Host -eq 'HOSTP' -and $_.Status -eq 'FIXED' })[0]).Detail | Should Be 'PILLARS=Patches'
        (@($out.Rows | Where-Object { $_.Host -eq 'HOSTZ' -and $_.Status -eq 'FIXED' })[0]).Detail | Should Be 'PILLARS=Patches'
    }

    It 'MANUAL mode announces itself in the activity log' {
        @($out.Logs | Where-Object { $_.text -match 'MANUAL MODE' }).Count | Should Not Be 0
    }

    It 'MANUAL mode de-dupes a short + FQDN of the same box (no destructive double-fix)' {
        $dd = Invoke-C2cFix -ActionId 'fix-firewall' -Params @{ targets = "HOSTP`nHOSTP.area52.afnoapps.usaf.mil"; confirm = 'FIX'; attemptOffline = $true }
        @($dd.Rows | Where-Object { $_.Host -eq 'HOSTP' -and $_.Status -eq 'FIXED' }).Count | Should Be 1
    }

    It 'MANUAL mode preserves an IPv4-literal target (never mangled to its first octet)' {
        # An operator types the IP of a DNS-broken box - the fix must dial 10.20.30.40, not "10".
        $ip = Invoke-C2cFix -ActionId 'fix-firewall' -Params @{ targets = '10.20.30.40'; confirm = 'FIX'; attemptOffline = $true }
        (@($ip.Rows | Where-Object { $_.Status -eq 'FIXED' })[0]).Host | Should Be '10.20.30.40'
    }

    It 'MANUAL mode still applies the self-guard (dispatcher/local host dropped)' {
        $sg = Invoke-C2cFix -ActionId 'fix-patches' -Params @{ targets = $env:COMPUTERNAME; confirm = 'FIX'; attemptOffline = $true }
        @($sg.Rows | Where-Object { $_.Status -eq 'FIXED' }).Count | Should Be 0
        (@($sg.Rows | Where-Object { $_.Status -eq 'SKIPPED' })[0]).Detail | Should Match 'self-guard'
    }
}

# -----------------------------------------------------------------------------
Describe 'C2C per-pillar fix - REFUSES a SUPPLIED-but-bad import / empty selection' {

    It 'with a csvPath pointing at an EMPTY / invalid CSV -> rejected, zero rows dialed' {
        $empty = New-C2cTempCsv ''
        try {
            $out = Invoke-C2cFix -ActionId 'fix-patches' -Params @{ targets = 'HOSTP'; csvPath = $empty; confirm = 'FIX' }
            $out.Result.summary.rejected | Should Be $true
            @($out.Rows).Count | Should Be 0
        } finally { Remove-Item -LiteralPath $empty -Force -ErrorAction SilentlyContinue }
    }

    It 'with a VALID csvPath but ZERO checked targets -> rejected (operator must check hosts in the tab)' {
        $csv = New-C2cTempCsv (@"
C2C Compliance Status:Compliance,C2C Compliance Status:Date,C2C Compliance Status:Age (Bucketed),Computer Name,Count
"Non-Compliant
Failed Rule - Patching",,,HOSTP.area52.afnoapps.usaf.mil,1
"@)
        try {
            $out = Invoke-C2cFix -ActionId 'fix-patches' -Params @{ targets = ''; csvPath = $csv; confirm = 'FIX' }
            $out.Result.summary.rejected | Should Be $true
            @($out.Rows).Count | Should Be 0
        } finally { Remove-Item -LiteralPath $csv -Force -ErrorAction SilentlyContinue }
    }

    It 'still enforces the confirm-word gate FIRST (bad confirm rejects before any CSV parse)' {
        $out = Invoke-C2cFix -ActionId 'fix-patches' -Params @{ targets = 'HOSTP'; csvPath = 'X:\no\such.csv'; confirm = 'nope' }
        $out.Result.summary.rejected | Should Be $true
        @($out.Rows).Count | Should Be 0
    }
}

# -----------------------------------------------------------------------------
Describe 'C2C run-all - UNION of per-tab selections, intersected with the re-derived CSV plan (not the whole fleet)' {

    # hostA fails Patches only, hostB fails Encryption only, hostC fails both.
    $csvBody = @"
C2C Compliance Status:Compliance,C2C Compliance Status:Date,C2C Compliance Status:Age (Bucketed),Computer Name,Count
"Non-Compliant
Failed Rule - Patching",,,hostA.area52.afnoapps.usaf.mil,1
"Non-Compliant
Failed Rule - Bitlocker",,,hostB.area52.afnoapps.usaf.mil,1
"Non-Compliant
Failed Rule - Patching
Failed Rule - Bitlocker",,,hostC.area52.afnoapps.usaf.mil,1
"@
    $csv = New-C2cTempCsv $csvBody
    # Client plan (from the view's per-tab checkboxes): hostA claims BOTH Patches and
    # Encryption (Encryption is an INTRUDER - the import only flagged hostA for Patches);
    # hostB claims Encryption; hostZ is not in the CSV at all.
    $plan = '[' +
            '{"host":"hostA","pillars":["Patches","Encryption"]},' +
            '{"host":"hostB","pillars":["Encryption"]},' +
            '{"host":"hostZ","pillars":["Patches"]}]'
    $out = Invoke-C2cFix -ActionId 'run-all' -Params @{ plan = $plan; csvPath = $csv; confirm = 'FIX'; attemptOffline = $true; threads = 4 }

    It 'dials hostA with Patches ONLY (the Encryption intruder pair is dropped)' {
        $a = @($out.Rows | Where-Object { $_.Host -eq 'hostA' -and $_.Status -eq 'FIXED' })[0]
        $a | Should Not BeNullOrEmpty
        $a.Detail | Should Be 'PILLARS=Patches'
        $a.Detail | Should Not Match 'Encryption'
    }

    It 'logs a warn naming the dropped host + pillar (hostA / Encryption)' {
        @($out.Logs | Where-Object { $_.level -eq 'warn' -and $_.text -match 'hostA' -and $_.text -match 'Encryption' }).Count | Should Not Be 0
    }

    It 'dials hostB per its own (valid) plan entry - Encryption' {
        $b = @($out.Rows | Where-Object { $_.Host -eq 'hostB' -and $_.Status -eq 'FIXED' })[0]
        $b | Should Not BeNullOrEmpty
        $b.Detail | Should Be 'PILLARS=Encryption'
    }

    It 'a client plan entry for a host NOT in the CSV is not dialed at all' {
        @($out.Rows | Where-Object { $_.Host -eq 'hostZ' -and $_.Status -eq 'FIXED' }).Count | Should Be 0
    }

    Remove-Item -LiteralPath $csv -Force -ErrorAction SilentlyContinue
}

# -----------------------------------------------------------------------------
Describe 'C2C run-all - MANUAL mode (no import) trusts the client plan verbatim' {

    # v1.12.0 dual-mode: run-all with NO csvPath dials each planned host for its own listed
    # fixable pillars, WITHOUT intersecting against a CSV (there is none). hostA gets both its
    # planned pillars; a plan host is no longer dropped for being "not in the import".
    It 'with a plan but NO csvPath -> MANUAL: dials each host for its planned pillars, NOT rejected' {
        $plan = '[{"host":"hostA","pillars":["Patches","Firewall"]},{"host":"hostB","pillars":["Encryption"]}]'
        $out = Invoke-C2cFix -ActionId 'run-all' -Params @{ plan = $plan; confirm = 'FIX'; attemptOffline = $true; threads = 4 }
        $out.Result.summary.rejected | Should Not Be $true
        $a = @($out.Rows | Where-Object { $_.Host -eq 'hostA' -and $_.Status -eq 'FIXED' })[0]
        $a | Should Not BeNullOrEmpty
        $a.Detail | Should Be 'PILLARS=Patches+Firewall'
        (@($out.Rows | Where-Object { $_.Host -eq 'hostB' -and $_.Status -eq 'FIXED' })[0]).Detail | Should Be 'PILLARS=Encryption'
    }

    It 'MANUAL run-all still drops non-endpoint-fixable pillars (Vuln/OSVersion route elsewhere)' {
        $plan = '[{"host":"hostA","pillars":["Patches","Vuln"]}]'
        $out = Invoke-C2cFix -ActionId 'run-all' -Params @{ plan = $plan; confirm = 'FIX'; attemptOffline = $true }
        (@($out.Rows | Where-Object { $_.Host -eq 'hostA' -and $_.Status -eq 'FIXED' })[0]).Detail | Should Be 'PILLARS=Patches'
    }
}

# -----------------------------------------------------------------------------
Describe 'C2C reachability probes WinRM HTTPS 5986 + auto -UseSSL (every worker)' {
    # v1.12.0: the scan, fix and version workers each probe 5985 -> 5986 -> 445 and switch
    # that host's session to -UseSSL when only 5986 answered. The decision is inline in each
    # pool-runspace scriptblock (no live listener to unit-test), so guard the wiring at source.
    # v1.17.0 adds a FOURTH worker - the read-only BitLocker escrow audit
    # ($script:C2cEscrowAuditBlock) - which carries the same ladder, so the pins are 4.
    # (These counts must be bumped by any commit that adds a worker: that is the point -
    # a new fan-out that quietly shipped the old 5985/445-only ladder turns this red.)
    $src = Get-Content -LiteralPath (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1') -Raw

    It 'every worker probes the 5985,5986,445 ladder (4 sites)' {
        ([regex]::Matches($src, '5985,5986,445')).Count | Should Be 4
    }
    It 'every worker arms -UseSSL for a 5986-only host (4 sites)' {
        ([regex]::Matches($src, "splat\['UseSSL'\]")).Count | Should Be 4
    }
    It 'every SSL session skips CA/CN validation for self-signed WinRM HTTPS (4 sites)' {
        ([regex]::Matches($src, "SkipCACheck")).Count | Should Be 4
    }
    It 'no worker still uses the old 5985,445-only ladder' {
        ([regex]::Matches($src, '5985,445')).Count | Should Be 0
    }
}

# -----------------------------------------------------------------------------
Describe 'fix-lockscreen stays a plain hostlist utility (no import required)' {

    # Regression guard for the v1.10.0 import-scoping rework: fix-lockscreen is an opt-in
    # cache fix - NOT a scored/CSV-mapped pillar - so it must BYPASS the import-scoped block
    # entirely and dial exactly the typed hostlist, even with NO csvPath. (A prior regression
    # routed it through the import block, where it was rejected 'No import loaded'.)

    It '(a) dials the typed host with the Lockscreen pillar - NO csvPath, NOT rejected' {
        $out = Invoke-C2cFix -ActionId 'fix-lockscreen' -Params @{ targets = 'FAKEHOST-ZZ01'; confirm = 'FIX' }
        $out.Result.summary.rejected | Should Not Be $true
        $h = @($out.Rows | Where-Object { $_.Host -eq 'FAKEHOST-ZZ01' -and $_.Status -eq 'FIXED' })[0]
        $h | Should Not BeNullOrEmpty
        $h.Detail | Should Be 'PILLARS=Lockscreen'
    }

    It '(b) still enforces the confirm-word gate FIRST (bad confirm -> rejected, zero dials)' {
        $out = Invoke-C2cFix -ActionId 'fix-lockscreen' -Params @{ targets = 'FAKEHOST-ZZ01'; confirm = 'nope' }
        $out.Result.summary.rejected | Should Be $true
        @($out.Rows).Count | Should Be 0
    }

    It '(c) still applies the self-guard - the dispatcher/local host is dropped (never dialed)' {
        $out = Invoke-C2cFix -ActionId 'fix-lockscreen' -Params @{ targets = $env:COMPUTERNAME; confirm = 'FIX' }
        @($out.Rows | Where-Object { $_.Status -eq 'FIXED' }).Count | Should Be 0
        $skip = @($out.Rows | Where-Object { $_.Status -eq 'SKIPPED' })[0]
        $skip | Should Not BeNullOrEmpty
        $skip.Detail | Should Match 'self-guard'
    }
}
