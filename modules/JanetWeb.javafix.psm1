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
#  The two security controls (ported verbatim from the Java-Cleanup-ScanFix v1.1
#  hardening) MUST NOT be weakened:
#    * VENDOR GATE     - '(?i)oracle|sun microsystems' : an installed product / a
#      JavaSoft residue key is only ever removed when a matching Oracle/Sun-published
#      Uninstall entry exists on the host (OpenJDK/Temurin/Corretto are NEVER touched).
#    * STRICT-GUID GUARD - '^\{[0-9A-Fa-f-]+\}$' : msiexec /x runs ONLY when the
#      Uninstall subkey name is a well-formed ProductCode GUID.
#
#  Contract:
#    Get-JanetJavaFixSrc                         -> the injectable source string
#    Get-JanetJavaVerdict  <Version> [MinUpdate] -> OLD / OK / UNKNOWN (heuristic)
#    Invoke-JanetJavaRemediation [-MinUpdate n]  -> one 'Java' rollup row object(s)
#                                                   @{ Name; Action; Result; Detail }
# =============================================================================

$script:JanetJavaFixSrc = @'
# Java verdict (Java-Cleanup-ScanFix v1.1 port). OLD / OK / UNKNOWN relative to
# 1.8.0_<MinUpdate>; UNKNOWN is NEVER auto-removed.
function Get-JanetJavaVerdict {
    param([string]$Version, [int]$MinUpdate = 491)
    $s = "$Version".Trim()
    if (-not $s) { return 'UNKNOWN' }
    # Old scheme: 1.8.0_281, 1.7.0, 1.2, 1.0.1 (legacy Java Web Start keys land here too)
    if ($s -match '^1\.(\d+)(?:\.(\d+))?(?:_(\d+))?$') {
        $maj = [int]$Matches[1]
        $upd = 0; if ($Matches[3]) { $upd = [int]$Matches[3] }
        if ($maj -lt 8) { return 'OLD' }
        if ($maj -eq 8 -and $upd -lt $MinUpdate) { return 'OLD' }
        return 'OK'
    }
    # Dotted scheme: 11.0.2 (modern JDK), 8.0.2810.9 (Oracle DisplayVersion), 2.8.281.9 (auto updater)
    if ($s -match '^(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?$') {
        $maj = [int]$Matches[1]
        if ($maj -ge 9) { return 'OK' }
        if ($maj -eq 8) {
            $u = [math]::Floor([int]$Matches[3] / 10)
            if ($u -lt $MinUpdate) { return 'OLD' }
            return 'OK'
        }
        return 'OLD'
    }
    # Bare major: 17, 21
    if ($s -match '^(\d+)$') { if ([int]$Matches[1] -ge 9) { return 'OK' } return 'OLD' }
    return 'UNKNOWN'
}

# Vendor-gated Java remediation (Java-Cleanup-ScanFix v1.1 port). Three evidence
# sources, then remove anything OLDER than 1.8.0_<MinUpdate>: (1) installed products
# (Uninstall registry native + WOW6432Node), Oracle/Sun PUBLISHER ONLY -> msiexec
# /x {GUID}; (2) JavaSoft registry residue (+ CurrentVersion repair, empty product
# keys dropped) gated on a matching Oracle/Sun install; (3) Program Files\Java folders.
# UNKNOWN versions are never auto-removed. Returns the single 'Java' rollup row(s).
function Invoke-JanetJavaRemediation {
    param([int]$MinUpdate = 491)
    $minUpd = $MinUpdate
    if (-not (Get-Command Get-JanetJavaVerdict -ErrorAction SilentlyContinue)) {
        return ,([pscustomobject]@{ Name='Java'; Action='none'; Result='FAIL'; Detail='Java verdict helper unavailable on target - nothing removed (fail-closed)' })
    }
    $jFinds = New-Object System.Collections.ArrayList
    $jAdd = { param($src, $name, $ver, $path) $jf = [pscustomobject]@{ Source=$src; Name=[string]$name; Version=[string]$ver; Path=[string]$path; Verdict=(Get-JanetJavaVerdict $ver $minUpd); Result=$null }; [void]$jFinds.Add($jf); $jf }

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
                    $newest = ($remaining.PSChildName | Sort-Object)[-1]
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

    # 3. Filesystem residue (Program Files Java dirs; in-use folders report FAILED)
    foreach ($root in @("$env:ProgramFiles\Java", "${env:ProgramFiles(x86)}\Java")) {
        if (-not $root -or -not (Test-Path $root)) { continue }
        foreach ($dir in @(Get-ChildItem $root -Directory -ErrorAction SilentlyContinue)) {
            $verJ = ''
            if ($dir.Name -match '(\d+(?:\.\d+)*(?:_\d+)?)') { $verJ = $Matches[1] }
            if (-not $verJ) {
                $exeJ = Join-Path $dir.FullName 'bin\java.exe'
                if (Test-Path $exeJ) { $verJ = "$((Get-Item $exeJ).VersionInfo.FileVersion)" }
            }
            $jf = & $jAdd 'FileSystem' $dir.Name $verJ $dir.FullName
            if ($jf.Verdict -eq 'OLD') {
                try { Remove-Item -LiteralPath $dir.FullName -Recurse -Force -ErrorAction Stop; $jf.Result = 'OK - folder removed' }
                catch { $jf.Result = "FAILED (likely in use): $($_.Exception.Message)" }
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
    $instOk  = @($jFinds | Where-Object { $_.Source -eq 'Installed' -and $_.Verdict -eq 'OK' })
    $instAll = @($jFinds | Where-Object { $_.Source -eq 'Installed' })
    $jState  = if ($instOk.Count -gt 0) { "CURRENT ($(@($instOk | ForEach-Object { $_.Version } | Sort-Object -Unique) -join ', '))" }
               elseif ($instAll.Count -eq 0) { 'NO JAVA INSTALLED' }
               else { 'NO CURRENT JAVA' }
    $oldTxt = (@($jOld | ForEach-Object { "$($_.Source):$($_.Version)$(if ("$($_.Result)" -like 'FAILED*') { ' [FAILED]' } elseif ("$($_.Result)" -like 'MANUAL*') { ' [MANUAL]' })" } | Sort-Object -Unique) -join '; ')
    if ($oldTxt.Length -gt 400) { $oldTxt = $oldTxt.Substring(0, 400) + ' ...' }
    $unkTxt = if ($jUnk.Count -gt 0) { "; $($jUnk.Count) UNKNOWN version(s) left for manual review" } else { '' }
    $out = New-Object System.Collections.ArrayList
    if ($jOld.Count -eq 0) {
        [void]$out.Add([pscustomobject]@{ Name='Java'; Action='none'; Result='NOCHANGE'; Detail="no Java older than 1.8.0_$minUpd found ($($jFinds.Count) finding(s), $($jOk.Count) OK); state: $jState$unkTxt" })
    } elseif ($jFailed.Count -eq 0 -and $jManual.Count -eq 0) {
        [void]$out.Add([pscustomobject]@{ Name='Java'; Action='cleanup'; Result='FIXED'; Detail="removed $($jFixed.Count) OLD item(s) [$oldTxt]; state: $jState$unkTxt" })
    } else {
        [void]$out.Add([pscustomobject]@{ Name='Java'; Action='cleanup'; Result='FAIL'; Detail="removed $($jFixed.Count), failed $($jFailed.Count), manual $($jManual.Count) of $($jOld.Count) OLD item(s) [$oldTxt]; state: $jState$unkTxt" })
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
