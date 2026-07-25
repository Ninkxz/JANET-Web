# =============================================================================
#  Acas.KbInstallStatus.Tests.ps1 - Pester 3.4 for the honest acas kb-install
#  status (loop25). A Fable deep-dive of the acas remediation engine found the
#  kb-install worker reported an unverified MECM InstallUpdates trigger (and a
#  UsoClient fire-and-forget) as OK - which books a VulnPatched Success audit and
#  lights the PATCHED stat card - and let any confirmed install mask a real error
#  (partial-fail-as-OK). These are the acas siblings of the wpt kb-install issues
#  fixed in loops 22-23. Now: any error -> FAIL; a trigger/fire with no confirmed
#  install -> UNCONFIRMED (AcasOkOf renders it amber, out of the OK/patched tally);
#  a confirmed MSU exit-0 install -> OK; only skips -> SKIP.
#
#  Get-AcasKbInstallStatus is the canonical rule; the AcasKbInstallBlock worker
#  mirrors it inline (it runs in a module-less runspace, can't call a module fn).
#  The real worker's status is exercised end-to-end by FixVerify2 (Invoke-AcasKb).
#
#  Pure function, no I/O. Run:  Invoke-Pester -Path .\tests\Acas.KbInstallStatus.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Force -PassThru

function Get-Status {
    param([int]$Err, [int]$Mecm, [int]$Msu, [int]$Skip, [bool]$Uso)
    (& $script:Mod { param($e, $m, $s, $k, $u) Get-AcasKbInstallStatus -ErrorCount $e -MecmTriggered $m -MsuInstalled $s -Skipped $k -UsoTriggered $u } $Err $Mecm $Msu $Skip $Uso)
}

Describe 'Get-AcasKbInstallStatus - a trigger is never "patched"' {
    It 'a MECM trigger with no confirmed install -> UNCONFIRMED (not OK)' {
        Get-Status -Err 0 -Mecm 2 -Msu 0 -Skip 0 -Uso $false | Should Be 'UNCONFIRMED'
    }
    It 'a UsoClient fire-and-forget -> UNCONFIRMED' {
        Get-Status -Err 0 -Mecm 0 -Msu 0 -Skip 0 -Uso $true | Should Be 'UNCONFIRMED'
    }
    It 'a confirmed MSU install (no trigger) -> OK' {
        Get-Status -Err 0 -Mecm 0 -Msu 1 -Skip 0 -Uso $false | Should Be 'OK'
    }
    It 'a MECM trigger alongside an MSU install still errs toward verify -> UNCONFIRMED' {
        Get-Status -Err 0 -Mecm 1 -Msu 1 -Skip 0 -Uso $false | Should Be 'UNCONFIRMED'
    }
}

Describe 'Get-AcasKbInstallStatus - an error never hides behind a partial install' {
    It 'any error -> FAIL, even with a confirmed MSU install (partial-fail no longer masks)' {
        Get-Status -Err 1 -Mecm 0 -Msu 1 -Skip 0 -Uso $false | Should Be 'FAIL'
    }
    It 'any error -> FAIL, even with a MECM trigger' {
        Get-Status -Err 1 -Mecm 1 -Msu 0 -Skip 0 -Uso $false | Should Be 'FAIL'
    }
}

Describe 'Get-AcasKbInstallStatus - skips and no-ops' {
    It 'nothing installed, only skips -> SKIP' {
        Get-Status -Err 0 -Mecm 0 -Msu 0 -Skip 2 -Uso $false | Should Be 'SKIP'
    }
    It 'nothing happened at all -> SKIP (never a bare OK)' {
        Get-Status -Err 0 -Mecm 0 -Msu 0 -Skip 0 -Uso $false | Should Be 'SKIP'
    }
}

# =============================================================================
#  audit 2026-07-24 (P2) - the ROW and the AUDIT disagreed. The worker's honest
#  'UNCONFIRMED ...' (an accepted MECM/UsoClient trigger, not a confirmed install)
#  hit the kb-install rowOf, which had no UNCONFIRMED branch, and fell through to
#  Result='OK' - green in the grid - while $script:AcasOkOf (the SAME string, the
#  predicate that drives the fan-out tally and the audit verdict) booked it as a
#  Failure. The rowOf is now hoisted beside its siblings and carries the branch.
# =============================================================================
function Get-KbRow { param([string]$Res) & $script:Mod { param($r) & $script:AcasKbInstallRowOf $r 'WS01' @{} } $Res }
function Get-KbOk  { param([string]$Res) & $script:Mod { param($r) [bool](& $script:AcasOkOf $r) } $Res }

Describe 'kb-install row - an unverified trigger is not painted green' {

    $unconf = 'UNCONFIRMED <<MECM=2>> <<MSU=0>> <<SKIP=0>> <<KBS=KB5000001>> MECM: triggered 2 update(s)'

    It 'an UNCONFIRMED MECM trigger renders UNCONFIRMED (was OK)' {
        (Get-KbRow $unconf).Result | Should Be 'UNCONFIRMED'
    }
    It 'a UsoClient fire-and-forget renders UNCONFIRMED (was OK)' {
        (Get-KbRow 'UNCONFIRMED <<MECM=0>> <<MSU=0>> <<SKIP=0>> <<KBS=KB5000001>> UsoClient triggered').Result | Should Be 'UNCONFIRMED'
    }
    It 'the row verdict and the audit ok-predicate AGREE on every worker status' {
        # not-ok (audit books Failure)  <=>  the row says FAIL or UNCONFIRMED.
        foreach ($r in @($unconf,
                         'OK <<MECM=0>> <<MSU=1>> <<SKIP=0>> <<KBS=KB1>> installed',
                         'FAIL <<MECM=0>> <<MSU=0>> <<SKIP=0>> <<KBS=KB1>> exit 5',
                         'SKIP <<MECM=0>> <<MSU=0>> <<SKIP=1>> <<KBS=KB1>> not in MECM')) {
            $bad = @('FAIL','UNCONFIRMED') -contains (Get-KbRow $r).Result
            $bad | Should Be (-not (Get-KbOk $r))
        }
    }
    It 'a confirmed MSU install is still OK (the honest green is untouched)' {
        (Get-KbRow 'OK <<MECM=0>> <<MSU=1>> <<SKIP=0>> <<KBS=KB1>> MSU installed (exit 0)').Result | Should Be 'OK'
    }
    It 'hoisting the rowOf kept the row SHAPE (markers parsed, detail stripped)' {
        $row = Get-KbRow $unconf
        $row.Host    | Should Be 'WS01'
        $row.KBs     | Should Be 'KB5000001'
        $row.MECM    | Should Be 2
        $row.MSU     | Should Be 0
        $row.Skipped | Should Be 0
        $row.Detail  | Should Match 'triggered 2 update'
        $row.Detail  | Should Not Match '<<'
    }
}

Describe 'acas - manifest version floor (loop-25 honest kb-install status landed at 1.11.6)' {
    It 'acas version is >= 1.11.6 (floor; exact pin lives in the newest bump test)' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        ([version][string]$mani.version -ge [version]'1.11.6') | Should Be $true
    }
}

# loop86: AcasKbInstallBlock is a DESTRUCTIVE worker (MECM InstallUpdates + wusa MSU + UsoClient install, and a
# reboot when NoReboot is off) that was the ONLY destructive acas fan-out MISSING the wrong-box (DNS-mismatch)
# guard its siblings carry (update worker ~:2004, reboot workers ~:2174/:2201). Stale DNS / a reused IP could
# install KBs on the WRONG machine. Now it verifies the answering box's $env:COMPUTERNAME == the dialed shortname
# before any install (IPv4-literal target skips the compare; empty probe proceeds). Same shape as the shared
# wrong-box guard in PkginstallSecureboot.WrongBoxGuard.Tests.ps1. Unit-scope: no host contact below.
$script:Src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Raw
function Get-KbExpectedName { param([string]$h) if ($h -match '^\d{1,3}(\.\d{1,3}){3}$') { '' } else { ($h -split '\.')[0] } }
function Test-KbWrongBoxAbort { param([string]$Target,[string]$Answering) $e = Get-KbExpectedName $Target; [bool]($Target -notmatch '^\d{1,3}(\.\d{1,3}){3}$' -and $Answering -and ($Answering.Trim().ToUpper() -ne $e.ToUpper())) }

Describe 'AcasKbInstallBlock wrong-box guard (loop86) - the destructive kb-install worker aborts on DNS mismatch' {
    It 'the guard is PRESENT in AcasKbInstallBlock before the install (COMPUTERNAME compare + hard-abort)' {
        # scope the assertion to the kb-install block body
        $blk = [regex]::Match($script:Src, '(?s)\$script:AcasKbInstallBlock\s*=\s*\{.*?\n\}').Value
        ($blk -match "\`$Computer -notmatch '\^\\d\{1,3\}\(\\\.\\d\{1,3\}\)\{3\}\$'")                 | Should Be $true
        ($blk -match '\$actualName\s*=\s*try \{ Invoke-Command -Session \$sess.*\$env:COMPUTERNAME')  | Should Be $true
        ($blk -match "DNS mismatch: dialed '\`$targetShort' but remote is.*ABORTED, no KBs installed") | Should Be $true
    }
    It 'the abort predicate: an FQDN whose box answers with a DIFFERENT name aborts' {
        Test-KbWrongBoxAbort 'WS01.area.af.mil' 'WS02' | Should Be $true
    }
    It 'the matching box (same shortname) does NOT abort' {
        Test-KbWrongBoxAbort 'WS01.area.af.mil' 'WS01' | Should Be $false
        Test-KbWrongBoxAbort 'WS01' 'ws01'             | Should Be $false   # case-insensitive
    }
    It 'an IPv4-literal target skips the compare (no shortname to match)' {
        (Get-KbExpectedName '10.1.2.3')            | Should Be ''
        Test-KbWrongBoxAbort '10.1.2.3' 'ANY-NAME' | Should Be $false
    }
    It 'an empty probe (COMPUTERNAME unreadable) proceeds - does not regress into a false abort' {
        Test-KbWrongBoxAbort 'WS01.area.af.mil' '' | Should Be $false
    }
    It 'acas manifest is at or past 1.11.15 (kb-install guard; exact pin migrated to the newest bump)' {
        ([version][string](& $script:Mod { (Get-JanetToolManifest).version }) -ge [version]'1.11.15') | Should Be $true
    }
}

# =============================================================================
#  audit 2026-07-25 (fable re-audit follow-up) - TEST GAP, not a code bug. Every
#  assertion above pokes $script:AcasKbInstallRowOf DIRECTLY, so nothing pinned the
#  kb-install SWITCH ARM to it: a regression that reintroduced an inline OK-only
#  rowOf inside the arm (which is exactly what the 1.11.19 fix hoisted out) would
#  have sailed through the whole suite while the grid went back to painting an
#  unverified MECM trigger green. These pin the ARM's wiring - and then EXERCISE the
#  rowOf expression the arm actually binds, so an inline replacement fails here.
# =============================================================================
Describe 'kb-install ARM is wired to the shared rowOf (audit 2026-07-25)' {

    # scope every assertion to the 'kb-install' switch-arm body (arms are indented 8)
    $arm    = [regex]::Match($script:Src, "(?s)'kb-install'\s*\{.*?\n        \}").Value
    $unconf = 'UNCONFIRMED <<MECM=2>> <<MSU=0>> <<SKIP=0>> <<KBS=KB5000001>> MECM: triggered 2 update(s)'

    It 'the arm body was located (guard against a silently empty regex scope)' {
        [bool]$arm                            | Should Be $true
        ($arm -match 'Invoke-AcasFanOut')     | Should Be $true
    }
    It 'the arm binds the HOISTED shared rowOf, not an inline scriptblock literal' {
        ($arm -match '\$rowOf\s*=\s*\$script:AcasKbInstallRowOf') | Should Be $true
        ($arm -match '\$rowOf\s*=\s*\{')                          | Should Be $false
    }
    It 'and hands THAT rowOf to the fan-out (no second, unpinned row builder)' {
        ($arm -match '-RowOf \$rowOf')                        | Should Be $true
        ([regex]::Matches($arm, '\$rowOf\s*=').Count)         | Should Be 1
    }
    It "the arm's OWN rowOf expression renders an unverified trigger UNCONFIRMED (an inline OK-only rowOf fails here)" {
        $expr = [regex]::Match($arm, '\$rowOf\s*=\s*(\$script:\w+)').Groups[1].Value
        $expr | Should Be '$script:AcasKbInstallRowOf'
        # evaluate the arm's expression in module scope and run the row builder it names
        $row = & $script:Mod ([scriptblock]::Create("param(`$r) & $expr `$r 'WS01' @{}")) $unconf
        [string]$row.Result | Should Be 'UNCONFIRMED'
        [string]$row.Host   | Should Be 'WS01'
    }
    It "the arm's rowOf and the audit ok-predicate still agree (row green <=> audit Success)" {
        $expr = [regex]::Match($arm, '\$rowOf\s*=\s*(\$script:\w+)').Groups[1].Value
        foreach ($r in @($unconf,
                         'OK <<MECM=0>> <<MSU=1>> <<SKIP=0>> <<KBS=KB1>> installed',
                         'FAIL <<MECM=0>> <<MSU=0>> <<SKIP=0>> <<KBS=KB1>> exit 5')) {
            $row = & $script:Mod ([scriptblock]::Create("param(`$r) & $expr `$r 'WS01' @{}")) $r
            $bad = @('FAIL','UNCONFIRMED') -contains [string]$row.Result
            $bad | Should Be (-not (Get-KbOk $r))
        }
    }
}

# =============================================================================
#  audit 2026-07-25 (fable re-audit follow-up) - the ambient reboot branch of
#  $script:AcasRebootWorker built shutdown.exe's arguments as an ARRAY. PS 5.1
#  joins -ArgumentList array elements with spaces and quotes NOTHING, so a
#  multi-word /c warning splintered into stray tokens. Same class as the wusa /
#  shutdown quoting bugs already fixed in this suite. Source-scoped: no host contact.
# =============================================================================
Describe 'ambient reboot: shutdown.exe /c is a QUOTED single argument (audit 2026-07-25)' {

    $blk = [regex]::Match($script:Src, '(?s)\$script:AcasRebootWorker\s*=\s*\{.*?\n\}').Value

    It 'the reboot worker body was located' {
        ($blk -match 'shutdown\.exe') | Should Be $true
    }
    It 'the unquoted ARRAY form is gone (the bug: /c splintered on the first space)' {
        ($blk -match "'/c',\s*\`$warn") | Should Be $false
    }
    It 'the /c value is passed as ONE double-quoted argument' {
        # one STRING; $warn wrapped in backtick-escaped double quotes so a multi-word
        # warning stays a single /c argument instead of splintering into stray tokens
        $blk.Contains('$shutArgs = "/m \\$Target /r /t 300 /c `"$warn`""')  | Should Be $true
        ($blk -match 'Start-Process .* -ArgumentList \$shutArgs')           | Should Be $true
    }
    It 'the credentialed path is untouched - $warn still round-trips as a real argument' {
        $blk.Contains('-ArgumentList $warn, $guardShort')         | Should Be $true
        $blk.Contains('shutdown.exe" /r /t 300 /c $w | Out-Null') | Should Be $true
    }
    It 'the sanitiser that makes the quoting safe is still in place (no embedded quote/newline)' {
        $blk.Contains('-replace ''[\r\n"]''')      | Should Be $true
        $blk.Contains('if ($warn.Length -gt 500)') | Should Be $true
    }
    It 'the wrong-box (DNS mismatch) hard-aborts are still on BOTH reboot paths' {
        ([regex]::Matches($blk, 'ABORTED, no reboot sent').Count) | Should Be 2
    }
}
