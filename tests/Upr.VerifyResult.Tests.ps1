# =============================================================================
#  Upr.VerifyResult.Tests.ps1 - Pester 3.4 for the upr post-uninstall verify
#  decision (Get-UprVerifyResult, loop35). A loop-35 deep-dive found upr's
#  removed/remediated decision fail-closed and honest end-to-end (exit-code gated,
#  a MANDATORY registry re-verify after every OK), verdict GREEN. The one
#  hardening: the verify demoted an OK to FAIL when the re-read THREW (catch), but
#  a non-throwing EMPTY ($null) remote result read `[bool]$null.Present` = $false
#  = "not present" = gone, so an empty verify result could let an OK stand. The
#  verify is the trust-critical step (it catches a lying uninstall), so a $null /
#  unreadable verify must fail CLOSED to "could NOT be verified", never "removed".
#
#  Get-UprVerifyResult is the canonical decision; the uninstall worker mirrors it
#  inline (runspace). Pure - tested.  Run:  Invoke-Pester -Path .\tests\Upr.VerifyResult.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$script:Mod  = Import-Module (Join-Path $script:Root 'modules\JanetWeb.upr.psm1') -Force -PassThru

function Get-Verify($VerifyOut, [bool]$Reboot = $false, [string]$AppResult = 'OK (removed)') {
    (& $script:Mod { param($v, $rb, $ar) Get-UprVerifyResult -VerifyOut $v -RebootNeeded $rb -AppResult $ar } $VerifyOut $Reboot $AppResult)
}

Describe 'Get-UprVerifyResult - the verify fails CLOSED, never reads empty-as-removed' {
    It 'a $null verify result (empty, non-throwing) -> could NOT be verified (the fix)' {
        Get-Verify $null | Should Match 'could NOT be verified'
    }
    It 'a $null verify result never reads as removed/OK' {
        (Get-Verify $null) -notmatch '^OK' | Should Be $true
    }
    It 'product still present -> FAIL (still present)' {
        Get-Verify ([pscustomobject]@{ Present = $true }) | Should Match 'still present'
    }
    It 'product confirmed gone -> the app result stands (OK)' {
        Get-Verify ([pscustomobject]@{ Present = $false }) -AppResult 'OK (removed)' | Should Be 'OK (removed)'
    }
    It 'product gone + reboot needed -> OK (removed, reboot required)' {
        Get-Verify ([pscustomobject]@{ Present = $false }) -Reboot $true | Should Match 'reboot required'
    }
}

Describe 'upr - manifest exact version pin (newest bump = loop-64 generic-handler hardening)' {
    It 'upr is at least v1.2.4 (floor; newest exact pin = loop74 hint Describe, v1.2.5)' {
        $mani = & $script:Mod { Get-JanetToolManifest }
        ([version][string]$mani.version -ge [version]'1.2.4') | Should Be $true
    }
}

# loop64: harden the generic uninstall handlers. (1) The MSI handler interpolated a registry-derived
# GUID into a single msiexec ArgumentList string - a crafted UninstallString GUID could inject extra
# switches under the operator credential; it now routes through the injection-safe Invoke-SafeUninstall /
# Get-SafeUninstallPlan (proven in Upr.UninstallStringParse.Tests). (2) The dead Store branch returned an
# unconditional "OK (Store app removed)" that a no-match pipeline never earned and the registry re-verify
# could not catch - a false-clean landmine; removed, so a future 'Store' type fail-closes via the EXE path.
# Static analysis - both handlers live inside the remote WinRM uninstall scriptblock.
Describe 'upr 1.2.4 - generic uninstall handlers: MSI injection-safe + no Store false-clean' {
    $mani = & $script:Mod { Get-JanetToolManifest }
    $src  = Get-Content (Join-Path $script:Root 'modules\JanetWeb.upr.psm1') -Raw

    It 'the MSI handler routes through the injection-safe Invoke-SafeUninstall' {
        $idxMsi  = $src.IndexOf("if (`$type -eq 'MSI')")
        $idxSafe = if ($idxMsi -ge 0) { $src.IndexOf('Invoke-SafeUninstall -UnStr $unStr', $idxMsi) } else { -1 }
        $idxElse = if ($idxMsi -ge 0) { $src.IndexOf('} else {', $idxMsi) } else { -1 }
        ($idxMsi -ge 0)  | Should Be $true
        # the MSI branch reaches an Invoke-SafeUninstall BEFORE its closing '} else {' (the EXE branch)
        ($idxSafe -gt $idxMsi -and $idxSafe -lt $idxElse) | Should Be $true
    }
    It 'the old raw msiexec ArgumentList GUID interpolation is gone' {
        ($src -match 'Start-Process msiexec -ArgumentList "/x') | Should Be $false
    }
    It 'the dead Store unconditional-OK branch is gone (no false-clean landmine)' {
        ($src -match 'OK \(Store app removed\)') | Should Be $false
        ($src -match "\`$type -eq 'Store'")      | Should Be $false
    }
    It 'the manifest no longer advertises a Store handler' {
        ($mani.summary -match 'Store') | Should Be $false
        $ru = @($mani.actions | Where-Object { $_.id -eq 'report-uninstall' })[0]
        ($ru.description -match 'Store') | Should Be $false
    }
}

# loop74 (informative-failures theme): the upr fan-out harvest now, on a host-level failure (unreachable
# / worker error, $res.Error set, -not $ok), runs the raw error through Get-JanetTroubleshootHint and
# attaches the hint to each emitted row (Hint field) + an err log (FIX:), raw error preserved. Static
# analysis (the harvest runs inside the fan-out over a real RunspacePool).
Describe 'upr 1.2.5 - fan-out attaches a troubleshooting hint to a failed host' {
    $mani = & $script:Mod { Get-JanetToolManifest }
    $src  = Get-Content (Join-Path $script:Root 'modules\JanetWeb.upr.psm1') -Raw

    It 'manifest version is at or past 1.2.5 (host-level hint; exact pin migrated to newest bump)' {
        ([version][string]$mani.version -ge [version]'1.2.5') | Should Be $true
    }
    It 'upr imports the shared troubleshoot engine' {
        ($src -match 'Import-Module.*JanetWeb\.troubleshoot\.psm1') | Should Be $true
    }
    It 'the harvest computes a host-level hint only on a failure with a raw error and attaches it to the row' {
        ($src -match '\$hint\s*=\s*if\s*\(\(-not \$ok\)\s*-and\s*\$res\.Error\)\s*\{\s*Get-JanetTroubleshootHint') | Should Be $true
        ($src -match "\`$row\['Hint'\]\s*=\s*\`$hint")                                                             | Should Be $true
    }
    It 'the host-level err log is gated on $hint and carries the FIX hint (raw error preserved)' {
        ($src -match "if \(\`$hint\) \{ &\s*\`$Send @\{ type='log'; level='err'") | Should Be $true
        ($src -match 'FIX: \$hint')                                              | Should Be $true
    }
}

# loop83/84 (informative-failures follow-up): the per-candidate uninstall-failure hint. loop 83 wired it
# INSIDE New-UprEmitRows, but that block is .GetNewClosure()'d and loses the upr module scope where
# Get-JanetTroubleshootHint lives -> the call threw CommandNotFoundException and aborted the whole run at
# the first failing candidate (loop84 P1 - the loop-83 static test never executed the closure). Fixed by
# moving the hint into Invoke-UprFanOut's harvest (module scope). These tests EXECUTE the closure (would
# have caught P1) + pin the harvest wire.
Describe 'upr 1.2.7 - per-candidate uninstall failure hint (P1: computed in module scope, not the closure)' {
    $mani = & $script:Mod { Get-JanetToolManifest }
    $src  = Get-Content (Join-Path $script:Root 'modules\JanetWeb.upr.psm1') -Raw

    It 'manifest version is at or past 1.2.7 (P1 harvest-scope fix; exact pin migrated to newest bump)' {
        ([version][string]$mani.version -ge [version]'1.2.7') | Should Be $true
    }
    It 'the New-UprEmitRows closure does NOT throw when invoked with a Failure candidate (P1 regression guard)' {
        # BEHAVIORAL: the closure must not call an unresolvable function (Get-JanetTroubleshootHint is not in
        # the .GetNewClosure() scope). loop-83 shipped a call here that threw CommandNotFoundException.
        $emit = & $script:Mod { New-UprEmitRows -DoUninstall $true -DryRun $false -Send {param($x)} }
        $res = @{ Host='WS01'; Reachable=$true; Error=$null; Candidates=@(@{ Product='OldJava'; Version='8'; Decision='Uninstall'; Result='FAIL (setup exit 1603)'; Plugin=''; Publisher=''; Type='MSI'; PSChildName='{x}'; Label='y'; UninstallString='z' }) }
        $threw = $false
        try { $out = & $emit $res $null } catch { $threw = $true }
        $threw | Should Be $false
        ([string]$out.rows[0]['Result']) | Should Be 'FAIL (setup exit 1603)'
    }
    It 'the closure does NOT compute the hint (no Get-JanetTroubleshootHint call inside New-UprEmitRows)' {
        # scope New-UprEmitRows body: from its header to the .GetNewClosure() that closes it
        $fn = [regex]::Match($src, '(?s)function New-UprEmitRows.*?\}\.GetNewClosure\(\)').Value
        ($fn -match 'Get-JanetTroubleshootHint') | Should Be $false
    }
    It 'the harvest (module scope) computes the per-candidate hint off the row Result + a FIX err log' {
        ($src -match "elseif \(\`$row\.ContainsKey\('Result'\)\)")                                    | Should Be $true
        ($src -match "\`$ch\s*=\s*Get-JanetTroubleshootHint\s*-Message\s*\`$rt")                       | Should Be $true
        ($src -match "if \(\`$ch\) \{[^}]*\`$row\['Hint'\] = \[string\]\`$ch")                          | Should Be $true
        ($src -match 'FIX: \$ch')                                                                     | Should Be $true
    }
}

# loop85 (P0): a candidate row carries an app 'Type' key, and the row-event emit was `@{ type='row' } + $row`,
# which THROWS on PS 5.1 (case-insensitive Hashtable: 'type' == 'Type' -> duplicate-key ArgumentException),
# aborting EVERY fan-out that found a candidate - one statement AFTER loop-84's P1 fix, so loop 84's "run
# un-broken" claim was false and the static tests never emitted a Type-bearing row. New-UprRowEvent builds the
# message in a case-SENSITIVE Hashtable so both keys survive to JSON. This test EXECUTES the emit.
Describe 'upr 1.2.8 - the row-event emit does NOT collide on a candidate Type key (P0)' {
    $mani = & $script:Mod { Get-JanetToolManifest }
    $src  = Get-Content (Join-Path $script:Root 'modules\JanetWeb.upr.psm1') -Raw

    It 'manifest version is at or past 1.2.8 (P0 row-emit fix; exact pin migrated to newest bump)' {
        ([version][string]$mani.version -ge [version]'1.2.8') | Should Be $true
    }
    It 'New-UprRowEvent does NOT throw on a Type-bearing row and keeps BOTH type + Type (case-sensitive)' {
        $row = @{ Host='WS01'; Product='OldJava'; Type='MSI'; Result='FAIL (setup exit 1603)' }
        $threw = $false; $msg = $null
        try { $msg = & $script:Mod { param($r) New-UprRowEvent $r } $row } catch { $threw = $true }
        $threw            | Should Be $false
        [string]$msg['type'] | Should Be 'row'
        [string]$msg['Type'] | Should Be 'MSI'
    }
    It 'the OLD colliding merge is GONE from the emit sites (no `@{ type=row } + $row`)' {
        # the only surviving mention is the explanatory comment in New-UprRowEvent
        ([regex]::Matches($src, "&\s*\`$[Ss]end\s*\(@\{ type='row' \} \+").Count) | Should Be 0
        ([regex]::Matches($src, "New-UprRowEvent \`$row").Count -ge 4)            | Should Be $true
    }
    It 'the plain @{type=row}+@{Type=..} merge really does throw on 5.1 (guards the root cause)' {
        $threw = $false
        try { $null = @{ type='row' } + @{ Type='EXE' } } catch { $threw = $true }
        $threw | Should Be $true
    }
    It 'New-UprRowEvent uses a case-SENSITIVE Hashtable (a plain @{} would re-introduce the collision)' {
        ($src -match 'New-Object System\.Collections\.Hashtable') | Should Be $true
    }
}

# audit 2026-07-24: over-removal + staging-safety pass. Behavioural coverage for the
# two headline findings lives in Upr.M365Scope.Tests.ps1 (M365 scoping) and
# Upr.RelaxedAttribution.Tests.ps1 (host attribution); these are the source-wire pins
# for the fixes that only exist inside the remote scriptblock / temp-file paths.
Describe 'upr 1.2.9 - scoped M365 removal + staging hardening (audit 2026-07-24)' {
    $mani = & $script:Mod { Get-JanetToolManifest }
    $src  = Get-Content (Join-Path $script:Root 'modules\JanetWeb.upr.psm1') -Raw

    It 'manifest version is exactly 1.2.10 (newest bump holds the exact pin)' {
        [string]$mani.version | Should Be '1.2.10'
    }
    # audit 2026-07-25 (fable re-audit follow-up): pkginstall creates its staging root
    # WITHOUT -Force so a squatted directory fails the host; upr used
    # '-Force -EA SilentlyContinue', i.e. the opposite decision about the same threat.
    It 'the staging directory is created EXCLUSIVELY (no -Force, failure not swallowed)' {
        ($src -match 'New-Item -Path \$cfgDir -ItemType Directory -EA Stop') | Should Be $true
        ($src -match 'New-Item -Path \$cfgDir -ItemType Directory -Force')   | Should Be $false
    }
    It 'only a staging directory this run created is cleaned up' {
        ($src -match 'if \(\$dirOk\) \{ Remove-Item -LiteralPath \$cfgDir -Recurse -Force') | Should Be $true
    }
    It 'the fleet-wide <Remove All="TRUE"/> Office config is GONE from the CODE' {
        # The phrase survives in the header + inline comments that explain the fix,
        # so only non-comment lines count here.
        $code = @(($src -split "`r?`n") | Where-Object { $_ -notmatch '^\s*#' })
        (@($code | Where-Object { $_ -match '(?i)<Remove\s+All=' }).Count) | Should Be 0
    }
    It 'the Office config XML is built around the SELECTED C2R product ID' {
        ($src -match '<Remove><Product ID=') | Should Be $true
    }
    It 'the staged config directory gets an explicit, NON-inherited DACL' {
        ($src -match 'SetAccessRuleProtection\(\$true, \$false\)') | Should Be $true
        # LocalSystem + BUILTIN\Administrators only
        ($src -match "'S-1-5-18',\s*'S-1-5-32-544'")              | Should Be $true
    }
    It 'the staged config is hash-verified before setup.exe consumes it' {
        ($src -match 'SHA256\]::Create\(\)')        | Should Be $true
        ($src -match '\$want -ne \$got')            | Should Be $true
    }
    It 'the Adobe candidate key is re-read with -LiteralPath (no GUID globbing)' {
        ($src -match 'Get-ItemProperty -LiteralPath \(Join-Path \$hive \$childName\)') | Should Be $true
    }
    It 'the pdftotext temp files are cleaned up on EVERY exit path (finally, not post-return)' {
        $fn = [regex]::Match($src, '(?s)function Parse-PdfFinding.*?\n\}').Value
        ($fn -match '(?s)\}\s*finally\s*\{[^}]*Remove-Item -LiteralPath \$tmpTxt') | Should Be $true
        ($fn -match '\$tmpErr')                                                    | Should Be $true
    }
}
