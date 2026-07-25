# =============================================================================
#  JanetWeb.javafix.psm1  ->  SHARED, pool-injectable Java remediation engine
#
#  ONE copy of c2c's hardened, vendor-gated (Oracle/Sun-only) Java removal, reused
#  by BOTH the C2C Readiness tool (fix-java pillar) and the Workstation Patching
#  Tool (fix-java action) - no copy-paste, so a future fix to the security logic
#  reaches both callers.
#
#  Both callers fan work into a [runspacefactory] pool whose worker runspaces are
#  built from InitialSessionState::CreateDefault() and have NO module scope. So the
#  engine is published as a SOURCE STRING ($script:JanetJavaFixSrc, returned by
#  Get-JanetJavaFixSrc) that each pool worker dot-sources; the same string is also
#  dot-sourced into THIS module scope so the functions resolve for unit tests.
#
#  The security controls (ported verbatim from the Java-Cleanup-ScanFix v1.1
#  hardening) MUST NOT be weakened:
#    * VENDOR GATE     - '(?i)oracle|sun microsystems' : an installed product / a
#      JavaSoft residue key is only ever removed when a matching Oracle/Sun-published
#      Uninstall entry exists on the host (OpenJDK/Temurin/Corretto are NEVER touched).
#    * FOLDER VENDOR GATE - the Program Files\Java sweep removes a tree ONLY on
#      POSITIVE Oracle/Sun evidence (Test-JanetJavaOracleTree: its bin\java.exe
#      publisher, or a matching Oracle/Sun Uninstall entry). Before audit 2026-07-24
#      that sweep had NO vendor gate and deleted a non-Oracle JDK 8 tree outright -
#      exactly the content the paragraph above promises is never touched.
#    * NON-RUNTIME COMPANIONS - Oracle's 'Java Auto Updater' (and friends) ship WITH
#      current Java on their own 2.8.x version line and are NOT runtimes. They are
#      never verdicted as a JRE and never removed (Test-JanetJavaRuntimeName,
#      audit 2026-07-24).
#    * STRICT-GUID GUARD - '^\{[0-9A-Fa-f-]+\}$' : msiexec /x runs ONLY when the
#      Uninstall subkey name is a well-formed ProductCode GUID.
#
#  Contract:
#    Get-JanetJavaFixSrc                                -> the injectable source string
#    Get-JanetJavaVerdict <Version> [MinUpdate] [Name]  -> OLD / OK / UNKNOWN (heuristic)
#    Invoke-JanetJavaRemediation [-MinUpdate n]         -> one 'Java' rollup row object(s)
#                                                          @{ Name; Action; Result; Detail }
#  Engine-internal helpers (dot-sourced with the rest, unit-tested via module scope):
#    Test-JanetJavaRuntimeName / Test-JanetJavaOracleTree / Get-JanetJavaVersionSortKey
# =============================================================================

$script:JanetJavaFixSrc = @'
# Is this product name an actual Java RUNTIME/JDK? (audit 2026-07-24)
# Oracle ships companion components whose DisplayName matches \bjava\b but which are
# NOT runtimes and carry their OWN version line - above all the 'Java Auto Updater'
# (DisplayVersion 2.8.491.9), which is INSTALLED BY CURRENT JAVA. Judging one of those
# as if it were a JRE msiexec-removed Oracle's own updater off fully COMPLIANT hosts.
# An empty name means the caller has no name to offer, so we judge on the version alone.
function Test-JanetJavaRuntimeName {
    param([string]$Name)
    $n = "$Name".Trim()
    if (-not $n) { return $true }
    if ($n -match '(?i)auto\s*updater|update\s*(?:checker|scheduler)|javafx|access\s*bridge|mission\s*control') { return $false }
    return $true
}

# Vendor gate for a Program Files\Java FOLDER (audit 2026-07-24). The filesystem sweep
# used to delete ANY old-looking tree, including a non-Oracle JDK 8 this module's header
# promises is never touched. A tree is now removed only on POSITIVE Oracle/Sun evidence,
# fail-closed:
#   * bin\java.exe published by Oracle/Sun -> owned (orphaned Oracle trees still cleaned)
#   * a binary published by anyone ELSE     -> NEVER (Temurin/Corretto/Zulu/Microsoft)
#   * no binary evidence at all             -> only when a matching Oracle/Sun Uninstall
#                                              entry exists on THIS host
function Test-JanetJavaOracleTree {
    param([string]$BinaryPublisher, [bool]$HasOracleInstall)
    $p = "$BinaryPublisher".Trim()
    if ($p -match '(?i)oracle|sun microsystems') { return $true }
    if ($p) { return $false }
    return [bool]$HasOracleInstall
}

# Version-aware sort key for a Java version string (audit 2026-07-24). '1.8.0_301' ->
# [version]1.8.0.301, so JavaSoft CurrentVersion is repointed to the genuinely newest
# remaining version. The LEXICAL string sort it replaces picked '1.8.0_91' over
# '1.8.0_301' and '9' over '11'. Unparseable input sorts lowest (0.0), never newest.
function Get-JanetJavaVersionSortKey {
    param([string]$Version)
    $t = ("$Version".Trim() -replace '_', '.')
    if ($t -match '^\d+$') { $t = "$t.0" }
    $sk = New-Object System.Version 0, 0
    try { $sk = [version]$t } catch {}
    return $sk
}

# Java verdict (Java-Cleanup-ScanFix v1.1 port). OLD / OK / UNKNOWN relative to
# 1.8.0_<MinUpdate>; UNKNOWN is NEVER auto-removed. Optional -Name lets a caller hand
# in the product name so a non-runtime Oracle companion is never judged as a JRE.
function Get-JanetJavaVerdict {
    param([string]$Version, [int]$MinUpdate = 491, [string]$Name = '')
    $s = "$Version".Trim()
    if (-not $s) { return 'UNKNOWN' }
    # audit 2026-07-24: only ACTUAL runtimes/JDKs get a version verdict at all.
    if (-not (Test-JanetJavaRuntimeName $Name)) { return 'UNKNOWN' }
    # Old scheme: 1.8.0_281, 1.7.0, 1.2, 1.0.1 (legacy Java Web Start keys land here too)
    if ($s -match '^1\.(\d+)(?:\.(\d+))?(?:_(\d+))?$') {
        $maj = [int]$Matches[1]
        $upd = 0; if ($Matches[3]) { $upd = [int]$Matches[3] }
        if ($maj -lt 8) { return 'OLD' }
        if ($maj -eq 8 -and $upd -lt $MinUpdate) { return 'OLD' }
        return 'OK'
    }
    # Dotted scheme: 11.0.2 (modern JDK), 8.0.2810.9 (Oracle DisplayVersion), 7.0.800 / 6.0.450 (legacy)
    if ($s -match '^(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?$') {
        $maj = [int]$Matches[1]
        if ($maj -ge 9) { return 'OK' }
        if ($maj -eq 8) {
            $u = [math]::Floor([int]$Matches[3] / 10)
            if ($u -lt $MinUpdate) { return 'OLD' }
            return 'OK'
        }
        # audit 2026-07-24: this used to fall through to a blanket 'OLD', which condemned
        # EVERY dotted version below 8 - including Oracle's CURRENT 'Java Auto Updater'
        # 2.8.491.9, msiexec-removed off compliant hosts. Java has never shipped a runtime
        # on a dotted major of 2-5 (Java 2..5 used the 1.x scheme); only 6/7 are the real
        # legacy Oracle DisplayVersion form. Anything lower is not a Java runtime version
        # at all -> UNKNOWN, and UNKNOWN is never auto-removed (fail-closed).
        if ($maj -ge 6) { return 'OLD' }
        return 'UNKNOWN'
    }
    # Bare major: 17, 21 (OK); 6/7/8 are real old majors; below that is not a Java runtime
    # major (those releases used the 1.x scheme) -> UNKNOWN, never removed (audit 2026-07-24).
    if ($s -match '^(\d+)$') {
        $mj = [int]$Matches[1]
        if ($mj -ge 9) { return 'OK' }
        if ($mj -ge 6) { return 'OLD' }
        return 'UNKNOWN'
    }
    return 'UNKNOWN'
}

# Vendor-gated Java remediation (Java-Cleanup-ScanFix v1.1 port). Three evidence
# sources, then remove anything OLDER than 1.8.0_<MinUpdate>: (1) installed products
# (Uninstall registry native + WOW6432Node), Oracle/Sun PUBLISHER ONLY and RUNTIMES
# ONLY -> msiexec /x {GUID}; (2) JavaSoft registry residue (+ CurrentVersion repair,
# empty product keys dropped) gated on a matching Oracle/Sun install; (3) Program
# Files\Java folders, gated on Oracle/Sun evidence for the tree (audit 2026-07-24).
# UNKNOWN versions are never auto-removed. Returns the single 'Java' rollup row(s).
function Invoke-JanetJavaRemediation {
    param([int]$MinUpdate = 491)
    $minUpd = $MinUpdate
    if (-not (Get-Command Get-JanetJavaVerdict -ErrorAction SilentlyContinue)) {
        return ,([pscustomobject]@{ Name='Java'; Action='none'; Result='FAIL'; Detail='Java verdict helper unavailable on target - nothing removed (fail-closed)' })
    }
    $jFinds = New-Object System.Collections.ArrayList
    # The finding's NAME is handed to the verdict too (audit 2026-07-24) so a non-runtime
    # Oracle companion can never be verdicted as a JRE, whatever its version string says.
    $jAdd = { param($src, $name, $ver, $path) $jf = [pscustomobject]@{ Source=$src; Name=[string]$name; Version=[string]$ver; Path=[string]$path; Verdict=(Get-JanetJavaVerdict $ver $minUpd $name); Result=$null }; [void]$jFinds.Add($jf); $jf }

    # Vendor gate for JavaSoft residue: capture the family|update token of EVERY
    # Oracle/Sun-published Uninstall entry found on THIS host. A JavaSoft version
    # subkey is pruned ONLY when its token is in this set - a JavaSoft key with no
    # matching Oracle/Sun install (e.g. OpenJDK/Corretto/Temurin residue) is LEFT
    # UNTOUCHED (registry version schemes differ, so match on family|update, not raw).
    $oracleKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $javaKey = {
        param([string]$v)
        $t = "$v".Trim()
        if ($t -match '^1\.(\d+)(?:\.(\d+))?(?:_(\d+))?$') { $u = 0; if ($Matches[3]) { $u = [int]$Matches[3] }; return ("$([int]$Matches[1])|$u") }
        if ($t -match '^(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?$') { $mj = [int]$Matches[1]; if ($mj -eq 8) { return ('8|' + [string][math]::Floor([int]$Matches[3] / 10)) } else { return ("$mj|0") } }
        return $null
    }

    # 1. Installed products (Uninstall keys, Oracle/Sun publisher only)
    foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
        if (-not (Test-Path $root)) { continue }
        foreach ($key in @(Get-ChildItem $root -ErrorAction SilentlyContinue)) {
            $pJ = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue
            if (-not $pJ) { continue }
            if ("$($pJ.DisplayName)" -notmatch '(?i)\bjava\b|\bj2se\b|\bjre\b|\bjdk\b') { continue }
            if ("$($pJ.Publisher)" -notmatch '(?i)oracle|sun microsystems') { continue }
            # audit 2026-07-24: the Oracle/Sun publisher gate happily admits Oracle's OWN
            # non-runtime companions - the 'Java Auto Updater' most of all, which current
            # Java installs alongside itself. Drop them here so they are neither removed
            # nor counted as a runtime in the rollup state.
            if (-not (Test-JanetJavaRuntimeName "$($pJ.DisplayName)")) { continue }
            $jf = & $jAdd 'Installed' "$($pJ.DisplayName)" "$($pJ.DisplayVersion)" $key.PSPath
            $okj = & $javaKey "$($pJ.DisplayVersion)"; if ($okj) { [void]$oracleKeys.Add($okj) }
            if ($jf.Verdict -eq 'OLD') {
                if ($key.PSChildName -match '^\{[0-9A-Fa-f-]+\}$') {
                    try {
                        $prc = Start-Process -FilePath 'msiexec.exe' -ArgumentList "/x $($key.PSChildName) /qn /norestart" -Wait -PassThru -ErrorAction Stop
                        switch ($prc.ExitCode) {
                            0       { $jf.Result = 'OK - uninstalled' }
                            3010    { $jf.Result = 'OK - uninstalled, reboot pending' }
                            1605    { $jf.Result = 'OK - orphan key (product was not actually installed)' }
                            default { $jf.Result = "FAILED: msiexec exit $($prc.ExitCode)" }
                        }
                    } catch { $jf.Result = "FAILED: $($_.Exception.Message)" }
                } else { $jf.Result = 'MANUAL: non-MSI uninstall entry - review manually' }
            }
        }
    }

    # 2. JavaSoft registry residue (native + WOW6432Node) + CurrentVersion repair
    foreach ($root in @('HKLM:\SOFTWARE\JavaSoft', 'HKLM:\SOFTWARE\WOW6432Node\JavaSoft')) {
        if (-not (Test-Path $root)) { continue }
        foreach ($product in @(Get-ChildItem $root -ErrorAction SilentlyContinue)) {
            foreach ($vk in @(Get-ChildItem $product.PSPath -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\d' })) {
                $jf = & $jAdd 'Registry' "$($product.PSChildName)" $vk.PSChildName $vk.PSPath
                if ($jf.Verdict -eq 'OLD') {
                    $jsKey = & $javaKey $vk.PSChildName
                    if ($jsKey -and $oracleKeys.Contains($jsKey)) {
                        try { Remove-Item -LiteralPath $vk.PSPath -Recurse -Force -ErrorAction Stop; $jf.Result = 'OK - key removed' }
                        catch { $jf.Result = "FAILED: $($_.Exception.Message)" }
                    } else {
                        $jf.Result = 'SKIP - no Oracle/Sun Uninstall entry for this version on host; JavaSoft key left untouched (may be OpenJDK/Corretto/Temurin residue)'
                    }
                }
            }
            # Repair CurrentVersion pointing at a removed version; drop empty product keys.
            try {
                $remaining = @(Get-ChildItem $product.PSPath -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\d' })
                $cvJ = (Get-ItemProperty $product.PSPath -ErrorAction SilentlyContinue).CurrentVersion
                if ($remaining.Count -eq 0) {
                    $hadVersions = @($jFinds | Where-Object { $_.Source -eq 'Registry' -and $_.Path -like "$($product.PSPath)*" -and $_.Result -like 'OK*' }).Count -gt 0
                    if ($hadVersions) {
                        Remove-Item -LiteralPath $product.PSPath -Recurse -Force -ErrorAction Stop
                        $jf2 = & $jAdd 'Registry' "$($product.PSChildName)" '' $product.PSPath
                        $jf2.Verdict = 'OLD'; $jf2.Result = 'OK - empty product key removed'
                    }
                }
                elseif ($cvJ -and ($remaining.PSChildName -notcontains $cvJ)) {
                    # audit 2026-07-24: this was a LEXICAL string sort, so it repointed
                    # CurrentVersion at the wrong build ('1.8.0_91' sorts above '1.8.0_301',
                    # '9' above '11'). Sort on the VERSION key instead, name as tie-break.
                    # The @() also guards the single-remaining case: indexing a bare string
                    # with [-1] yields its last CHARACTER, not the string.
                    $newest = @($remaining.PSChildName | Sort-Object -Property @{ Expression = { Get-JanetJavaVersionSortKey $_ } }, @{ Expression = { "$_" } })[-1]
                    Set-ItemProperty -Path $product.PSPath -Name CurrentVersion -Value $newest -ErrorAction Stop
                    $jf3 = & $jAdd 'Registry' "$($product.PSChildName)" "CurrentVersion -> $newest" $product.PSPath
                    $jf3.Verdict = 'OK'; $jf3.Result = 'OK - CurrentVersion repointed to newest remaining version'
                }
            } catch {
                $jf4 = & $jAdd 'Registry' "$($product.PSChildName)" '' $product.PSPath
                $jf4.Verdict = 'OLD'; $jf4.Result = "FAILED (product key cleanup): $($_.Exception.Message)"
            }
        }
    }

    # 3. Filesystem residue (Program Files Java dirs; in-use folders report FAILED).
    #    VENDOR-GATED (audit 2026-07-24): this sweep had NO vendor gate at all, so a
    #    non-Oracle JDK 8 tree unpacked under Program Files\Java (Temurin/Corretto/Zulu -
    #    content this module's header promises is NEVER touched) was deleted outright.
    #    Removal now needs POSITIVE Oracle/Sun evidence via Test-JanetJavaOracleTree: the
    #    tree's own bin\java.exe publisher, or a matching Oracle/Sun Uninstall entry
    #    ($oracleKeys, populated by step 1 above). Anything unproven SKIPs, fail-closed.
    foreach ($root in @("$env:ProgramFiles\Java", "${env:ProgramFiles(x86)}\Java")) {
        if (-not $root -or -not (Test-Path $root)) { continue }
        foreach ($dir in @(Get-ChildItem $root -Directory -ErrorAction SilentlyContinue)) {
            $verJ = ''
            if ($dir.Name -match '(\d+(?:\.\d+)*(?:_\d+)?)') { $verJ = $Matches[1] }
            # Read the tree's own java.exe once: it carries BOTH the fallback version and
            # the publisher (CompanyName) the vendor gate needs.
            $pubJ = ''
            $exeJ = Join-Path $dir.FullName 'bin\java.exe'
            if (Test-Path $exeJ) {
                try {
                    $viJ  = (Get-Item $exeJ -ErrorAction Stop).VersionInfo
                    $pubJ = "$($viJ.CompanyName)"
                    if (-not $verJ) { $verJ = "$($viJ.FileVersion)" }
                } catch {}
            }
            $jf = & $jAdd 'FileSystem' $dir.Name $verJ $dir.FullName
            if ($jf.Verdict -eq 'OLD') {
                $fsKeyJ = & $javaKey $verJ
                if (-not (Test-JanetJavaOracleTree $pubJ ([bool]($fsKeyJ -and $oracleKeys.Contains($fsKeyJ))))) {
                    $jf.Result = "SKIP - vendor gate: no Oracle/Sun evidence for this tree (binary publisher $(if ($pubJ) { "'$pubJ'" } else { 'unknown' }); no matching Oracle/Sun Uninstall entry on host); folder left untouched (may be OpenJDK/Corretto/Temurin)"
                } else {
                    try { Remove-Item -LiteralPath $dir.FullName -Recurse -Force -ErrorAction Stop; $jf.Result = 'OK - folder removed' }
                    catch { $jf.Result = "FAILED (likely in use): $($_.Exception.Message)" }
                }
            }
        }
    }

    # Rollup: one 'Java' row. Only 'Installed' findings count as a working runtime.
    $jOld    = @($jFinds | Where-Object { $_.Verdict -eq 'OLD' })
    $jOk     = @($jFinds | Where-Object { $_.Verdict -eq 'OK' })
    $jUnk    = @($jFinds | Where-Object { $_.Verdict -eq 'UNKNOWN' })
    $jFixed  = @($jOld | Where-Object { "$($_.Result)" -like 'OK*' })
    $jFailed = @($jOld | Where-Object { "$($_.Result)" -like 'FAILED*' })
    $jManual = @($jOld | Where-Object { "$($_.Result)" -like 'MANUAL*' })
    # audit 2026-07-24: a vendor-gated SKIP (and an OLD find left with no result at all)
    # was counted in NO bucket, so 'nothing failed' read as 'everything fixed' and a host
    # where we removed EXACTLY NOTHING booked FIXED - which the callers turn into a
    # VulnPatched Success audit. A no-op is not a remediated vulnerability; count them.
    $jSkip   = @($jOld | Where-Object { "$($_.Result)" -like 'SKIP*' -or -not "$($_.Result)" })
    $instOk  = @($jFinds | Where-Object { $_.Source -eq 'Installed' -and $_.Verdict -eq 'OK' })
    $instAll = @($jFinds | Where-Object { $_.Source -eq 'Installed' })
    $jState  = if ($instOk.Count -gt 0) { "CURRENT ($(@($instOk | ForEach-Object { $_.Version } | Sort-Object -Unique) -join ', '))" }
               elseif ($instAll.Count -eq 0) { 'NO JAVA INSTALLED' }
               else { 'NO CURRENT JAVA' }
    $oldTxt = (@($jOld | ForEach-Object { "$($_.Source):$($_.Version)$(if ("$($_.Result)" -like 'FAILED*') { ' [FAILED]' } elseif ("$($_.Result)" -like 'MANUAL*') { ' [MANUAL]' } elseif ("$($_.Result)" -like 'SKIP*' -or -not "$($_.Result)") { ' [SKIPPED]' })" } | Sort-Object -Unique) -join '; ')
    if ($oldTxt.Length -gt 400) { $oldTxt = $oldTxt.Substring(0, 400) + ' ...' }
    $unkTxt = if ($jUnk.Count -gt 0) { "; $($jUnk.Count) UNKNOWN version(s) left for manual review" } else { '' }
    $skipTxt = if ($jSkip.Count -gt 0) { ", $($jSkip.Count) left untouched by the Oracle/Sun vendor gate" } else { '' }
    $out = New-Object System.Collections.ArrayList
    if ($jOld.Count -eq 0) {
        [void]$out.Add([pscustomobject]@{ Name='Java'; Action='none'; Result='NOCHANGE'; Detail="no Java older than 1.8.0_$minUpd found ($($jFinds.Count) finding(s), $($jOk.Count) OK); state: $jState$unkTxt" })
    } elseif ($jFixed.Count -eq 0 -and $jFailed.Count -eq 0 -and $jManual.Count -eq 0) {
        # Every OLD find was gated away: we removed NOTHING, so this is a no-op, not a fix
        # (audit 2026-07-24 - it used to fall into the FIXED branch below and book a
        # 'removed 0 OLD item(s)' success).
        [void]$out.Add([pscustomobject]@{ Name='Java'; Action='none'; Result='NOCHANGE'; Detail="found $($jOld.Count) OLD item(s) but removed NOTHING - all were left untouched by the Oracle/Sun vendor gate [$oldTxt]; state: $jState$unkTxt" })
    } elseif ($jFailed.Count -eq 0 -and $jManual.Count -eq 0) {
        [void]$out.Add([pscustomobject]@{ Name='Java'; Action='cleanup'; Result='FIXED'; Detail="removed $($jFixed.Count) of $($jOld.Count) OLD item(s)$skipTxt [$oldTxt]; state: $jState$unkTxt" })
    } else {
        [void]$out.Add([pscustomobject]@{ Name='Java'; Action='cleanup'; Result='FAIL'; Detail="removed $($jFixed.Count), failed $($jFailed.Count), manual $($jManual.Count)$skipTxt of $($jOld.Count) OLD item(s) [$oldTxt]; state: $jState$unkTxt" })
    }
    return $out.ToArray()
}
'@

# Dot-source the engine into THIS module scope so Get-JanetJavaVerdict /
# Invoke-JanetJavaRemediation resolve for module-scope callers and unit tests.
try { . ([scriptblock]::Create($script:JanetJavaFixSrc)) } catch {}

# The injectable source string, for pool workers that must dot-source it in a bare
# runspace with no module scope (c2c's $JavaSrc arg / wpt's WptFixJavaBlock).
function Get-JanetJavaFixSrc { $script:JanetJavaFixSrc }

Export-ModuleMember -Function Get-JanetJavaFixSrc, Get-JanetJavaVerdict, Invoke-JanetJavaRemediation
