# =============================================================================
#  JavaFix.VendorGate.Tests.ps1 - Pester 3.4 for the audit 2026-07-24 fixes to the
#  SHARED Java remediation engine (modules\JanetWeb.javafix.psm1 - the ONE copy
#  c2c's fix-java pillar, wpt's fix-java action and acas' Java-Remove profile call).
#
#  PURE / offline unit scope - no real host, no registry write, no msiexec, no
#  Remove-Item. Everything here is either a pure helper call in module scope or an
#  assertion on the injectable engine SOURCE string. We pin:
#   (1) the version verdict only judges ACTUAL Java runtimes/JDKs, so Oracle's
#       CURRENT 'Java Auto Updater' 2.8.491.9 is never OLD (it was msiexec-removed
#       off COMPLIANT hosts) while a genuinely old 1.8.0_301 still is;
#   (2) the Program Files\Java sweep is VENDOR-GATED (Test-JanetJavaOracleTree), so
#       a non-Oracle JDK 8 tree - which the module header promises is never touched -
#       is left alone;
#   (3) a run that removed NOTHING books NOCHANGE, never FIXED (no-op != remediated);
#   (4) JavaSoft CurrentVersion is repointed by a VERSION sort, not a lexical one.
#
#  Run:  Invoke-Pester -Path .\tests\JavaFix.VendorGate.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$jm = Import-Module (Join-Path $script:Root 'modules\JanetWeb.javafix.psm1') -Force -PassThru

Describe 'javafix audit 2026-07-24 (1) - only ACTUAL Java runtimes get a version verdict' {

    # The bug: the dotted-version branch fell through to a blanket 'OLD' for every major
    # below 8, so Oracle's Java Auto Updater (2.8.491.9 - installed BY current Java, an
    # Oracle-published Uninstall entry with a well-formed ProductCode GUID) was verdicted
    # OLD and msiexec /x'd off hosts that were fully compliant.
    It 'Oracle CURRENT Java Auto Updater 2.8.491.9 is NOT OLD (so it is never removed)' {
        (& $jm { Get-JanetJavaVerdict '2.8.491.9' }) | Should Not Be 'OLD'
        (& $jm { Get-JanetJavaVerdict '2.8.491.9' }) | Should Be 'UNKNOWN'   # UNKNOWN is never auto-removed
    }
    It 'every 2.x auto-updater build is equally safe (the whole 2.x line is not a runtime)' {
        (& $jm { Get-JanetJavaVerdict '2.8.281.9' }) | Should Be 'UNKNOWN'
        (& $jm { Get-JanetJavaVerdict '2.5.0.1' })   | Should Be 'UNKNOWN'
        (& $jm { Get-JanetJavaVerdict '3.0.1' })     | Should Be 'UNKNOWN'
        (& $jm { Get-JanetJavaVerdict '5.0.100' })   | Should Be 'UNKNOWN'
    }
    It 'a genuinely old JRE 1.8.0_301 is STILL OLD (the fix does not blunt the remediation)' {
        (& $jm { Get-JanetJavaVerdict '1.8.0_301' }) | Should Be 'OLD'
        (& $jm { Get-JanetJavaVerdict '1.7.0' })     | Should Be 'OLD'
        (& $jm { Get-JanetJavaVerdict '1.6.0_45' })  | Should Be 'OLD'
    }
    It 'the real dotted legacy majors (Oracle 6.x/7.x DisplayVersion) are still OLD' {
        (& $jm { Get-JanetJavaVerdict '7.0.800' }) | Should Be 'OLD'
        (& $jm { Get-JanetJavaVerdict '6.0.450' }) | Should Be 'OLD'
    }
    It 'the 1.8.0_491 bar and the modern-JDK verdicts are unchanged' {
        (& $jm { Get-JanetJavaVerdict '1.8.0_491' })  | Should Be 'OK'
        (& $jm { Get-JanetJavaVerdict '8.0.2810.9' }) | Should Be 'OLD'   # 8u281
        (& $jm { Get-JanetJavaVerdict '8.0.4910.9' }) | Should Be 'OK'    # 8u491
        (& $jm { Get-JanetJavaVerdict '11.0.2' })     | Should Be 'OK'
        (& $jm { Get-JanetJavaVerdict '17' })         | Should Be 'OK'
        (& $jm { Get-JanetJavaVerdict '8' })          | Should Be 'OLD'   # bare 8, update unknown
        (& $jm { Get-JanetJavaVerdict 'banana' })     | Should Be 'UNKNOWN'
        (& $jm { Get-JanetJavaVerdict '' })           | Should Be 'UNKNOWN'
    }
    It 'a custom MinUpdate bar is still honoured (signature stayed backward compatible)' {
        (& $jm { Get-JanetJavaVerdict '1.8.0_281' 271 }) | Should Be 'OK'
        (& $jm { Get-JanetJavaVerdict '1.8.0_261' 271 }) | Should Be 'OLD'
    }

    # Second line of defence: the optional -Name says WHAT the version belongs to, so a
    # non-runtime companion can never be judged as a JRE whatever its version looks like.
    It 'Test-JanetJavaRuntimeName rejects Oracle non-runtime companions, accepts real runtimes' {
        (& $jm { Test-JanetJavaRuntimeName 'Java Auto Updater' })                    | Should Be $false
        (& $jm { Test-JanetJavaRuntimeName 'Java Access Bridge' })                   | Should Be $false
        (& $jm { Test-JanetJavaRuntimeName 'JavaFX 2.1.1' })                         | Should Be $false
        (& $jm { Test-JanetJavaRuntimeName 'Java 8 Update 301' })                    | Should Be $true
        (& $jm { Test-JanetJavaRuntimeName 'Java(TM) SE Development Kit 8 Update 301' }) | Should Be $true
        (& $jm { Test-JanetJavaRuntimeName '' })                                     | Should Be $true   # no name -> judge on version
    }
    It 'a runtime-looking version carried by a NON-runtime name is not OLD either' {
        (& $jm { Get-JanetJavaVerdict '1.8.0_301' 491 'Java Auto Updater' }) | Should Be 'UNKNOWN'
        (& $jm { Get-JanetJavaVerdict '1.8.0_301' 491 'Java 8 Update 301' }) | Should Be 'OLD'
    }
    It 'the sweep drops non-runtime companions before they are ever considered for removal' {
        $src = & $jm { Get-JanetJavaFixSrc }
        $src | Should Match ([regex]::Escape('if (-not (Test-JanetJavaRuntimeName "$($pJ.DisplayName)")) { continue }'))
        # ...and the finding's NAME is handed to the verdict for every evidence source.
        $src | Should Match ([regex]::Escape('Get-JanetJavaVerdict $ver $minUpd $name'))
    }
}

Describe 'javafix audit 2026-07-24 (2) - the Program Files\Java sweep is VENDOR-GATED' {

    # The bug: step 3 deleted ANY folder whose name/binary version verdicted OLD, with no
    # publisher check at all - so a Temurin/Corretto/Zulu JDK 8 tree unpacked under
    # Program Files\Java was destroyed, the exact content the module header promises is
    # NEVER touched.
    It 'an Oracle/Sun-published java.exe is owned (orphaned Oracle trees are still cleaned)' {
        (& $jm { Test-JanetJavaOracleTree 'Oracle Corporation' $false })     | Should Be $true
        (& $jm { Test-JanetJavaOracleTree 'Oracle America, Inc.' $false })   | Should Be $true
        (& $jm { Test-JanetJavaOracleTree 'Sun Microsystems, Inc.' $false }) | Should Be $true
    }
    It 'a NON-Oracle java.exe is NEVER owned - even when the host also has an Oracle install' {
        (& $jm { Test-JanetJavaOracleTree 'Eclipse Adoptium' $true })   | Should Be $false   # Temurin
        (& $jm { Test-JanetJavaOracleTree 'Amazon.com, Inc.' $true })   | Should Be $false   # Corretto
        (& $jm { Test-JanetJavaOracleTree 'Azul Systems, Inc.' $true }) | Should Be $false   # Zulu
        (& $jm { Test-JanetJavaOracleTree 'Microsoft' $true })          | Should Be $false
    }
    It 'no binary evidence -> removal requires a matching Oracle/Sun Uninstall entry (fail-closed)' {
        (& $jm { Test-JanetJavaOracleTree '' $true })  | Should Be $true
        (& $jm { Test-JanetJavaOracleTree '' $false }) | Should Be $false
        (& $jm { Test-JanetJavaOracleTree '   ' $false }) | Should Be $false
    }
    It 'the folder Remove-Item is reachable ONLY through the gate, and a gated tree SKIPs' {
        $src = & $jm { Get-JanetJavaFixSrc }
        $src | Should Match ([regex]::Escape('if (-not (Test-JanetJavaOracleTree $pubJ'))
        $src | Should Match 'SKIP - vendor gate'
        # The pre-fix code removed the tree straight off the OLD verdict with no gate:
        # the gate must now come BEFORE the only folder Remove-Item in the engine.
        $gateIdx = $src.IndexOf('Test-JanetJavaOracleTree $pubJ')
        $rmIdx   = $src.IndexOf('Remove-Item -LiteralPath $dir.FullName')
        ($gateIdx -gt 0)        | Should Be $true
        ($rmIdx -gt $gateIdx)   | Should Be $true
    }
    It 'the gate reads the publisher from the tree own bin\java.exe' {
        $src = & $jm { Get-JanetJavaFixSrc }
        $src | Should Match ([regex]::Escape('$pubJ = "$($viJ.CompanyName)"'))
    }
}

Describe 'javafix audit 2026-07-24 (3) - a run that removed NOTHING is NOCHANGE, not FIXED' {

    # The bug: SKIP results landed in no bucket, so 'nothing failed' read as 'everything
    # fixed' and a host where the vendor gate blocked every removal still booked FIXED -
    # which acas/c2c/wpt turn into a VulnPatched Success audit.
    $src = & $jm { Get-JanetJavaFixSrc }

    It 'SKIPped / result-less OLD finds are counted in their own bucket' {
        $src | Should Match ([regex]::Escape('$jSkip   = @($jOld | Where-Object { "$($_.Result)" -like ''SKIP*'''))
    }
    It 'the FIXED branch is guarded by jFixed.Count (0 removed can no longer reach it)' {
        $src | Should Match ([regex]::Escape('elseif ($jFixed.Count -eq 0 -and $jFailed.Count -eq 0 -and $jManual.Count -eq 0)'))
        $src | Should Match ([regex]::Escape('removed NOTHING'))
        # The no-op row uses a Result the callers already map to SKIP, not to a success.
        $src | Should Match ([regex]::Escape('Action=''none''; Result=''NOCHANGE''; Detail="found'))
    }
    It 'the skipped count is surfaced in the FIXED and FAIL details too' {
        $src | Should Match ([regex]::Escape('$skipTxt'))
        $src | Should Match ([regex]::Escape(' [SKIPPED]'))
    }
}

Describe 'javafix audit 2026-07-24 (4) - JavaSoft CurrentVersion repoint sorts as VERSIONS' {

    It 'the sort key orders Java update levels numerically (lexical got this backwards)' {
        $a = & $jm { Get-JanetJavaVersionSortKey '1.8.0_301' }
        $b = & $jm { Get-JanetJavaVersionSortKey '1.8.0_91' }
        ($a -gt $b) | Should Be $true
        # Proof the old code was wrong: the lexical comparison says the opposite.
        ('1.8.0_301' -gt '1.8.0_91') | Should Be $false
    }
    It 'the exact repoint expression picks the genuinely newest remaining version' {
        $newest = & $jm {
            @(@('1.8.0_91', '1.8.0_301', '1.8.0_45') |
                Sort-Object -Property @{ Expression = { Get-JanetJavaVersionSortKey $_ } }, @{ Expression = { "$_" } })[-1]
        }
        $newest | Should Be '1.8.0_301'
    }
    It 'modern bare majors sort numerically too (9 is not newer than 11/17)' {
        $newest = & $jm {
            @(@('9', '11', '17') |
                Sort-Object -Property @{ Expression = { Get-JanetJavaVersionSortKey $_ } }, @{ Expression = { "$_" } })[-1]
        }
        $newest | Should Be '17'
    }
    It 'an unparseable version subkey sorts LOWEST, so it can never be picked as newest' {
        $junk = & $jm { Get-JanetJavaVersionSortKey 'banana' }
        $real = & $jm { Get-JanetJavaVersionSortKey '1.8.0_301' }
        ($junk -lt $real) | Should Be $true
        [string]$junk | Should Be '0.0'
    }
    It 'a SINGLE remaining version repoints to the version, not to its last character' {
        # The old ($x | Sort-Object)[-1] returned a CHAR when $x was one bare string.
        $only = & $jm {
            @(@('1.8.0_301') |
                Sort-Object -Property @{ Expression = { Get-JanetJavaVersionSortKey $_ } }, @{ Expression = { "$_" } })[-1]
        }
        $only | Should Be '1.8.0_301'
    }
    It 'the engine no longer carries the lexical sort' {
        $src = & $jm { Get-JanetJavaFixSrc }
        $src | Should Not Match ([regex]::Escape('($remaining.PSChildName | Sort-Object)[-1]'))
        $src | Should Match ([regex]::Escape('Sort-Object -Property @{ Expression = { Get-JanetJavaVersionSortKey $_ } }'))
    }
}

Describe 'javafix audit 2026-07-28 - phantom OLD finds and no-op removals are not booked as fixes' {

    $src = & $jm { Get-JanetJavaFixSrc }

    It 'the JavaSoft verdict sweep skips the bare FAMILY-POINTER key (1.8 next to 1.8.0_491)' {
        # A bare '1.8' parses as maj=8/upd=0 and verdicts OLD, so a host whose only Java is
        # CURRENT reported "found 1 OLD item(s) but removed NOTHING". Verify both halves:
        # the verdict really is OLD, and the sweep filter really excludes the key.
        (& $jm { Get-JanetJavaVerdict '1.8' }) | Should Be 'OLD'
        $src | Should Match ([regex]::Escape("-match '^\d' -and `$_.PSChildName -notmatch '^\d+\.\d+$'"))
    }
    It 'the CurrentVersion repair still counts the family key, so a compliant host is not repointed' {
        # Deliberate asymmetry - $remaining feeds a -notcontains test against CurrentVersion.
        $src | Should Match ([regex]::Escape('$remaining = @(Get-ChildItem $product.PSPath -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match ''^\d'' })'))
    }
    It 'msiexec 1605 is MANUAL, never an OK* string (OK* buckets as FIXED -> a VulnPatched Success)' {
        $src | Should Match '1605\s*\{ \$jf\.Result = ''MANUAL:'
        $src | Should Not Match ([regex]::Escape("1605    { `$jf.Result = 'OK"))
    }
}

Describe 'javafix audit 2026-07-24 - the pre-existing security guards are UNTOUCHED' {

    $src = & $jm { Get-JanetJavaFixSrc }

    It 'the Oracle/Sun publisher vendor gate is still verbatim in the source' {
        $src | Should Match ([regex]::Escape('(?i)oracle|sun microsystems'))
    }
    It 'the strict-GUID msiexec guard is still verbatim in the source' {
        $src | Should Match ([regex]::Escape('^\{[0-9A-Fa-f-]+\}$'))
    }
    It 'the engine still exposes the same three exported entry points' {
        (& $jm { (Get-Command Get-JanetJavaFixSrc).Name })         | Should Be 'Get-JanetJavaFixSrc'
        (& $jm { (Get-Command Get-JanetJavaVerdict).Name })        | Should Be 'Get-JanetJavaVerdict'
        (& $jm { (Get-Command Invoke-JanetJavaRemediation).Name }) | Should Be 'Invoke-JanetJavaRemediation'
    }
    It 'the injectable source still parses standalone (what every pool worker dot-sources)' {
        $errs = $null
        [void][System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$errs)
        @($errs).Count | Should Be 0
    }
}
