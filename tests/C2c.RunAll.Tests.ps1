# =============================================================================
#  C2c.RunAll.Tests.ps1 - Pester 3.4 tests for the C2C v1.4.0 'run-all' action
#  (fix each imported non-compliant host's OWN failed pillars only) and the
#  pillar-flavoured result label map.
#
#  No WinRM call ever leaves this box:
#    * plan-parse / self-guard / confirm / pki-abort cases short-circuit or are
#      driven with the per-host worker ($script:C2cFixBlock) swapped for a
#      self-contained ECHO shim that just returns the pillar set it received, so
#      the runspace fan-out runs locally and every host row carries its own set.
#    * the label-map case runs the REAL worker LOCALLY with New-PSSession /
#      Invoke-Command / Get-Service shimmed IN MODULE SCOPE (the Enable-test
#      idiom), so the pillar-flavoured labels are produced without a remote.
#
#  Run:  Invoke-Pester -Path .\tests\C2c.RunAll.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
# -----------------------------------------------------------------------------
# Shim hygiene (audit 2026-07-25). Every shim teardown in this file used to be spelled
# 'Remove-Item function:script:<name>'. That spelling is INERT: the function provider has no
# scope qualifier in its paths, so 'function:script:X' names an item that does not exist and
# the -ErrorAction SilentlyContinue swallowed the failure - the shim SURVIVED into every later
# Describe/It in the file, where a test could then pass on a leaked stub. The naive correction
# ('Remove-Item function:X') is worse when the shim shadows a MODULE function: it deletes the
# real one. So snapshot first, then put back exactly what was there - the captured ScriptBlock
# for a module function, or nothing at all for a shimmed CMDLET (which had no function entry
# to begin with, and whose shim the unqualified path does remove).
function Add-ShimGuard {
    param($Mod)
    & $Mod {
        function script:Save-ShimState {
            param([string[]]$Names)
            $h = @{}
            foreach ($n in $Names) {
                $i = Get-Item -LiteralPath "function:$n" -ErrorAction SilentlyContinue
                if ($i) { $h[$n] = $i.ScriptBlock } else { $h[$n] = $null }
            }
            return $h
        }
        function script:Restore-ShimState {
            param($State)
            foreach ($k in @($State.Keys)) {
                if ($State[$k]) { Set-Item -LiteralPath "function:script:$k" -Value $State[$k] }
                else { Remove-Item -LiteralPath "function:$k" -ErrorAction SilentlyContinue }
            }
        }
    }
}
# -----------------------------------------------------------------------------
$cm = Import-Module (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1') -Force -PassThru
Add-ShimGuard $cm

# v1.10.0: run-all is import-scoped - it re-derives the plan from a CSV (csvPath) and
# INTERSECTS the client plan against it. For these tests (which assert the client-plan
# handling: unknown-pillar drop, per-host isolation, self-guard, PkiRoots bundle) we
# synthesize a CSV whose re-derived plan is a SUPERSET of the client plan's fixable
# pillars, so the new intersection is a NO-OP and every legacy assertion holds unchanged.
# A test can pass -CsvOverride to supply a deliberately-mismatched CSV instead.
function New-C2cPlanCsv {
    param([string]$PlanJson)
    $ruleFor = @{ Monitoring = 'Continuous Monitoring'; Firewall = 'Host Firewall'; Encryption = 'Bitlocker'; AntiMalware = 'MDE Health'; Patches = 'Patching'; PkiRoots = 'PKI Trust Roots' }
    $fixable = @('Monitoring', 'Firewall', 'Encryption', 'AntiMalware', 'Patches', 'PkiRoots')
    # PS 5.1 ConvertFrom-Json emits a top-level array as ONE pipeline object, so assign
    # FIRST then @()-wrap (piping straight into @() would collapse to a 1-element array).
    $parsed = $null
    try { $parsed = $PlanJson | ConvertFrom-Json } catch { $parsed = $null }
    $entries = @($parsed)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('C2C Compliance Status:Compliance,C2C Compliance Status:Date,C2C Compliance Status:Age (Bucketed),Computer Name,Count')
    foreach ($e in $entries) {
        $h = ''
        try { $h = [string]$e.host } catch { $h = '' }
        if (-not $h) { continue }
        $fx = @(@($e.pillars | ForEach-Object { [string]$_ }) | Where-Object { $fixable -contains $_ } | Select-Object -Unique)
        if ($fx.Count -eq 0) { continue }   # a client host with no fixable pillar need not appear
        $lines = @('Non-Compliant') + @($fx | ForEach-Object { 'Failed Rule - ' + $ruleFor[$_] })
        [void]$sb.AppendLine('"' + ($lines -join "`n") + '",,,' + $h + '.area52.afnoapps.usaf.mil,1')
    }
    $p = Join-Path ([System.IO.Path]::GetTempPath()) ("c2c_runall_{0}.csv" -f ([guid]::NewGuid().ToString('N')))
    Set-Content -LiteralPath $p -Value $sb.ToString() -Encoding UTF8
    return $p
}

# Run the 'run-all' action with the per-host worker swapped for an ECHO shim that
# reports the EXACT pillar set each host was dialed with (Detail 'PILLARS=a+b').
function Invoke-C2cRunAll {
    # -DefaultBundleOverride shims Get-C2cDefaultCertBundlePath (the shipped-bundle
    # resolver) for the duration so the auto-default behaviour is tested hermetically
    # WITHOUT depending on the real Packages\DoD-Certs folder: pass a missing path to
    # exercise the "no usable bundle -> PkiRoots skipped" path, or a real temp bundle to
    # exercise the "blank path auto-uses the shipped default" path. Restored via the
    # save/restore idiom (never Remove-Item, which would delete the module's real fn).
    param([string]$Plan, [string]$Confirm = 'FIX', [string]$CertBundleFolder = '', [bool]$Enable = $false, [bool]$Shim = $true, [string]$DefaultBundleOverride, [string]$CsvOverride)
    $script:__rows = New-Object System.Collections.ArrayList
    $script:__logs = New-Object System.Collections.ArrayList
    $emit = {
        param($e)
        if     ($e -and $e.type -eq 'row') { [void]$script:__rows.Add($e) }
        elseif ($e -and $e.type -eq 'log') { [void]$script:__logs.Add($e) }
    }
    $overrideDefault = $PSBoundParameters.ContainsKey('DefaultBundleOverride')
    if ($overrideDefault) {
        & $cm { param($p) $script:__origGDBP = ${function:Get-C2cDefaultCertBundlePath}; ${function:Get-C2cDefaultCertBundlePath} = { $p }.GetNewClosure() } $DefaultBundleOverride
    }
    if ($Shim) {
        & $cm {
            $script:__origFixBlock = $script:C2cFixBlock
            # v1.6.0 worker signature grows: + BundleJson, WinrmHeal, WinrmHealSrc (echoed/ignored here).
            $script:C2cFixBlock = {
                param([string]$Computer, $Cred, [string]$Auth, [bool]$AttemptOffline, [string[]]$Pillars, [bool]$DoEnable, [string]$TaniumService, [string]$TaniumInstalledSrc, [string]$BundleJson, [bool]$WinrmHeal, [string]$WinrmHealSrc)
                $ps = @(@($Pillars) | ForEach-Object { [string]$_ })
                @{ Host = $Computer; Ping = 'shim'; Status = 'FIXED'; Detail = ('PILLARS=' + ($ps -join '+'));
                   Report = ''; Pillars = @($ps | ForEach-Object { [pscustomobject]@{ Name = $_; Action = 'shim'; Result = 'FIXED'; Detail = 'shim' } }) }
            }
        }
    }
    # Import-scoped run-all needs a csvPath. Synthesize one that matches the plan (so the
    # server-side intersection is a no-op) unless the caller supplied -CsvOverride.
    $usingOverride = $PSBoundParameters.ContainsKey('CsvOverride')
    $csvForPlan = if ($usingOverride) { $CsvOverride } else { New-C2cPlanCsv $Plan }
    try {
        $params = @{ plan = $Plan; confirm = $Confirm; attemptOffline = $true; threads = 4 }
        if ($csvForPlan) { $params['csvPath'] = $csvForPlan }
        if ($CertBundleFolder) { $params['certBundleFolder'] = $CertBundleFolder }
        if ($Enable)  { $params['enableEncryption'] = $true }
        $res = Invoke-JanetToolAction -ActionId 'run-all' -Params $params -Credential $null -Emit $emit
    } finally {
        if ($Shim) { & $cm { $script:C2cFixBlock = $script:__origFixBlock; Remove-Variable -Name __origFixBlock -Scope Script -ErrorAction SilentlyContinue } }
        if ($overrideDefault) { & $cm { ${function:Get-C2cDefaultCertBundlePath} = $script:__origGDBP; Remove-Variable -Name __origGDBP -Scope Script -ErrorAction SilentlyContinue } }
        if (-not $usingOverride -and $csvForPlan) { Remove-Item -LiteralPath $csvForPlan -Force -ErrorAction SilentlyContinue }
    }
    [pscustomobject]@{ Result = $res; Rows = @($script:__rows); Logs = @($script:__logs) }
}

# Run the REAL fix-monitoring worker LOCALLY (Enable-test shim idiom) so the
# installed-registry probe + pillar label map are exercised end-to-end. Scenarios:
#   healthy      - installed + service Running/Automatic  -> NOCHANGE (ALREADY MONITORED)
#   healed       - installed + service Stopped/Manual->run -> FIXED (MONITORED)
#   notinstalled - NOT installed + service absent          -> FAIL (deploy from Software Center)
#   svcabsent    - installed + service ABSENT              -> FAIL (repair via Software Center)
# The uninstall-registry probe (Get-ItemProperty) and Get-Service are shimmed IN
# MODULE SCOPE so nothing touches the real registry / SCM and no WinRM leaves the box.
function Invoke-C2cMonitoring {
    param([string]$Scenario)
    & $cm {
        param($Scenario)
        $__shims = Save-ShimState @('New-PSSession','Remove-PSSession','Invoke-Command','Get-ItemProperty',
            'Get-Service','Set-Service','Start-Service')
        function script:New-PSSession { param($ComputerName, $SessionOption, $Authentication, $ErrorAction, $Credential) [pscustomobject]@{ Id = 1; Name = 'shim' } }
        function script:Remove-PSSession { param($Session, $ErrorAction) }
        function script:Invoke-Command {
            param($Session, $ComputerName, $ScriptBlock, $ArgumentList, $ErrorAction, $Credential, $Authentication, $SessionOption)
            if ($ScriptBlock -and ($ScriptBlock.ToString().Trim() -eq '$env:COMPUTERNAME')) { return $env:COMPUTERNAME }
            return (& $ScriptBlock @ArgumentList)
        }
        $script:__svcCalls = 0
        $script:__scn = $Scenario
        $script:__installed = ($Scenario -eq 'healthy' -or $Scenario -eq 'healed' -or $Scenario -eq 'svcabsent')
        # Uninstall-registry probe fake: one 'Tanium Client' DisplayName when installed.
        function script:Get-ItemProperty {
            param($Path, $LiteralPath, $ErrorAction)
            if ($script:__installed) { return [pscustomobject]@{ DisplayName = 'Tanium Client'; DisplayVersion = '7.4.5.1234' } }
            return @()
        }
        function script:Get-Service {
            param($Name, $ErrorAction)
            $script:__svcCalls++
            if ($script:__scn -eq 'healthy') { return [pscustomobject]@{ Name = $Name; Status = 'Running'; StartType = 'Automatic' } }
            if ($script:__scn -eq 'healed') {
                if ($script:__svcCalls -le 1) { return [pscustomobject]@{ Name = $Name; Status = 'Stopped'; StartType = 'Manual' } }
                return [pscustomobject]@{ Name = $Name; Status = 'Running'; StartType = 'Automatic' }
            }
            # notinstalled / svcabsent -> the Tanium client service is not present.
            return $null
        }
        function script:Set-Service { param($Name, $StartupType, $ErrorAction) }
        function script:Start-Service { param($Name, $ErrorAction) }
        try {
            # target = self so the wrong-box guard passes; Pillars = Monitoring only.
            # Real $C2cAddCertsSrc injected like production so the admin-side rollup labels via the
            # shared Get-C2cPillarLabel (audit 2026-07-23 deferred pass: inline fallback retired).
            $res = & $script:C2cFixBlock $env:COMPUTERNAME $null 'Default' $true @('Monitoring') $false 'Tanium Client' $script:C2cTaniumInstalledSrc $null $false $script:C2cWinrmHealSrc $script:C2cAddCertsSrc
            $mon = @(@($res.Pillars) | Where-Object { $_.Name -eq 'Monitoring' })[0]
            [pscustomobject]@{
                Status    = [string]$res.Status
                Detail    = [string]$res.Detail
                Report    = [string]$res.Report
                MonResult = $(if ($mon) { [string]$mon.Result } else { '' })
                MonDetail = $(if ($mon) { [string]$mon.Detail } else { '' })
            }
        } finally {
            # audit 2026-07-25: this teardown was 'Remove-Item function:script:<name>' - an INERT path
            # (the function provider has no scope qualifier), so the shims leaked. See Add-ShimGuard above.
            Restore-ShimState $__shims
        }
    } $Scenario
}

# Drive the READ-ONLY scan probe's Monitoring check (check #1) LOCALLY. Get-Service +
# the uninstall-registry probe are shimmed; other checks run against the real (read-only)
# cmdlets on this box but we only assert the Monitoring check's Status.
#   installedRunning - installed + service Running -> PASS
#   notinstalled     - not installed + service absent -> FAIL
function Invoke-C2cScanMonitoring {
    param([string]$Scenario)
    & $cm {
        param($Scenario)
        $__shims = Save-ShimState @('New-PSSession','Remove-PSSession','Invoke-Command','Get-ItemProperty',
            'Get-Service')
        function script:New-PSSession { param($ComputerName, $SessionOption, $Authentication, $ErrorAction, $Credential) [pscustomobject]@{ Id = 1; Name = 'shim' } }
        function script:Remove-PSSession { param($Session, $ErrorAction) }
        function script:Invoke-Command {
            param($Session, $ComputerName, $ScriptBlock, $ArgumentList, $ErrorAction, $Credential, $Authentication, $SessionOption)
            if ($ScriptBlock -and ($ScriptBlock.ToString().Trim() -eq '$env:COMPUTERNAME')) { return $env:COMPUTERNAME }
            return (& $ScriptBlock @ArgumentList)
        }
        $script:__inst = ($Scenario -eq 'installedRunning')
        function script:Get-ItemProperty {
            param($Path, $LiteralPath, $ErrorAction)
            if ($script:__inst) { return [pscustomobject]@{ DisplayName = 'Tanium Client'; DisplayVersion = '7.4.5.1234' } }
            return @()
        }
        function script:Get-Service {
            param($Name, $ErrorAction)
            if ($script:__inst) { return [pscustomobject]@{ Name = $Name; Status = 'Running'; StartType = 'Automatic' } }
            return $null
        }
        try {
            $cfg = Get-C2cBaselineDefaults
            # AttemptOffline = $true so the TCP short-circuit is skipped; target = self.
            $res = & $script:C2cProbeBlock $env:COMPUTERNAME $null 'Default' $true $cfg $script:C2cTaniumInstalledSrc
            $mon = @(@($res.Checks) | Where-Object { $_.Name -eq 'Monitoring' })[0]
            [pscustomobject]@{
                MonStatus = $(if ($mon) { [string]$mon.Status } else { '' })
                MonDetail = $(if ($mon) { [string]$mon.Detail } else { '' })
            }
        } finally {
            # audit 2026-07-25: this teardown was 'Remove-Item function:script:<name>' - an INERT path
            # (the function provider has no scope qualifier), so the shims leaked. See Add-ShimGuard above.
            Restore-ShimState $__shims
        }
    } $Scenario
}

# -----------------------------------------------------------------------------
Describe 'C2C run-all - plan JSON parse, unknown-pillar drop, zero-fixable info row' {

    # RA1: one fixable (Encryption) + one off-tool (Vuln, dropped).
    # RA2: only off-tool pillars -> zero fixable -> info row, never dialed.
    # RA3: two fixable pillars, preserved in order.
    $plan = '[' +
            '{"host":"RA1","pillars":["Encryption","Vuln"]},' +
            '{"host":"RA2","pillars":["Vuln","OSVersion"]},' +
            '{"host":"RA3","pillars":["AntiMalware","Firewall"]}]'
    $out = Invoke-C2cRunAll -Plan $plan

    It '(a) dials each host with ONLY its known fixable pillars (unknown pillar dropped)' {
        $ra1 = @($out.Rows | Where-Object { $_.Host -eq 'RA1' -and $_.Status -eq 'FIXED' })[0]
        $ra1 | Should Not BeNullOrEmpty
        $ra1.Detail | Should Be 'PILLARS=Encryption'
        $ra1.Detail | Should Not Match 'Vuln'
    }

    It '(a) logs a warn when a non-endpoint-fixable pillar is dropped' {
        @($out.Logs | Where-Object { $_.level -eq 'warn' -and $_.text -match 'RA1' -and $_.text -match 'Vuln' }).Count | Should Not Be 0
    }

    It '(a) a zero-fixable host gets an info/SKIPPED row and is NEVER dialed' {
        $ra2 = @($out.Rows | Where-Object { $_.Host -eq 'RA2' })
        $ra2.Count | Should Not Be 0
        ($ra2[0].Detail) | Should Match 'nothing endpoint-fixable'
        @($out.Rows | Where-Object { $_.Host -eq 'RA2' -and $_.Status -eq 'FIXED' }).Count | Should Be 0
    }

    It '(a) a multi-pillar host is dialed with its full known set' {
        $ra3 = @($out.Rows | Where-Object { $_.Host -eq 'RA3' -and $_.Status -eq 'FIXED' })[0]
        $ra3 | Should Not BeNullOrEmpty
        $ra3.Detail | Should Match 'AntiMalware'
        $ra3.Detail | Should Match 'Firewall'
    }
}

# -----------------------------------------------------------------------------
Describe 'C2C run-all - PkiRoots needs a cert bundle (auto-defaults to the shipped bundle; skipped only when neither is present)' {

    It '(b) with NEITHER a bundle NOR a usable shipped default, PkiRoots is skipped per host (info); a PkiRoots-only host is a zero-fixable row; other hosts still run' {
        $plan = '[{"host":"RB1","pillars":["PkiRoots"]},{"host":"RB2","pillars":["PkiRoots","AntiMalware"]}]'
        # No certBundleFolder AND the shipped default shimmed to a missing path -> no usable bundle.
        $out = Invoke-C2cRunAll -Plan $plan -DefaultBundleOverride 'X:\no\such\shipped\default\bundle'
        # RB1 (PkiRoots only, no bundle) -> zero endpoint-fixable -> info/SKIPPED row, never dialed.
        $rb1 = @($out.Rows | Where-Object { $_.Host -eq 'RB1' })[0]
        $rb1 | Should Not BeNullOrEmpty
        ($rb1.Detail) | Should Match 'nothing endpoint-fixable'
        # RB2 keeps only AntiMalware (PkiRoots skipped for lack of a bundle).
        $rb2 = @($out.Rows | Where-Object { $_.Host -eq 'RB2' -and $_.Status -eq 'FIXED' })[0]
        $rb2 | Should Not BeNullOrEmpty
        $rb2.Detail | Should Be 'PILLARS=AntiMalware'
        $rb2.Detail | Should Not Match 'PkiRoots'
        # the PkiRoots skip is logged (info) and names the host + PkiRoots.
        @($out.Logs | Where-Object { $_.text -match 'RB2' -and $_.text -match 'PkiRoots' }).Count | Should Not Be 0
        $out.Result.summary.rejected | Should BeNullOrEmpty
    }

    It '(b2) WITH a valid cert bundle folder, PkiRoots STAYS in the dialed set' {
        # Build a throwaway bundle folder with one self-signed .cer under root\.
        $bundleRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("c2c_bundle_{0}" -f ([guid]::NewGuid().ToString('N')))
        $rootDir = Join-Path $bundleRoot 'root'
        New-Item -ItemType Directory -Path $rootDir -Force | Out-Null
        $cert = New-SelfSignedCertificate -Subject 'CN=C2C-Test-Root' -CertStoreLocation 'Cert:\CurrentUser\My' -KeyExportPolicy Exportable -KeyLength 2048 -NotAfter (Get-Date).AddDays(1)
        [System.IO.File]::WriteAllBytes((Join-Path $rootDir 'testroot.cer'), $cert.RawData)
        Remove-Item ("Cert:\CurrentUser\My\{0}" -f $cert.Thumbprint) -Force -ErrorAction SilentlyContinue
        try {
            $plan = '[{"host":"RB3","pillars":["PkiRoots","AntiMalware"]}]'
            $out = Invoke-C2cRunAll -Plan $plan -CertBundleFolder $bundleRoot
            $rb3 = @($out.Rows | Where-Object { $_.Host -eq 'RB3' -and $_.Status -eq 'FIXED' })[0]
            $rb3 | Should Not BeNullOrEmpty
            $rb3.Detail | Should Match 'PkiRoots'
            $rb3.Detail | Should Match 'AntiMalware'
        } finally {
            Remove-Item -LiteralPath $bundleRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It '(b3) with a BLANK certBundleFolder, PkiRoots AUTO-uses the shipped default and STAYS in the dialed set' {
        # A real temp bundle stands in for the shipped Packages\DoD-Certs default (shimmed).
        $bundleRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("c2c_default_{0}" -f ([guid]::NewGuid().ToString('N')))
        $rootDir = Join-Path $bundleRoot 'root'
        New-Item -ItemType Directory -Path $rootDir -Force | Out-Null
        $cert = New-SelfSignedCertificate -Subject 'CN=C2C-Shipped-Default' -CertStoreLocation 'Cert:\CurrentUser\My' -KeyExportPolicy Exportable -KeyLength 2048 -NotAfter (Get-Date).AddDays(1)
        [System.IO.File]::WriteAllBytes((Join-Path $rootDir 'defaultroot.cer'), $cert.RawData)
        Remove-Item ("Cert:\CurrentUser\My\{0}" -f $cert.Thumbprint) -Force -ErrorAction SilentlyContinue
        try {
            $plan = '[{"host":"RB4","pillars":["PkiRoots","AntiMalware"]}]'
            # NO certBundleFolder supplied; the shipped default is shimmed to the temp bundle.
            $out = Invoke-C2cRunAll -Plan $plan -DefaultBundleOverride $bundleRoot
            $rb4 = @($out.Rows | Where-Object { $_.Host -eq 'RB4' -and $_.Status -eq 'FIXED' })[0]
            $rb4 | Should Not BeNullOrEmpty
            $rb4.Detail | Should Match 'PkiRoots'          # auto-default kept PkiRoots in the set
            $rb4.Detail | Should Match 'AntiMalware'
            # the cert-bundle log names the shipped-default source.
            @($out.Logs | Where-Object { $_.text -match '(?i)shipped default' }).Count | Should Not Be 0
        } finally {
            Remove-Item -LiteralPath $bundleRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# -----------------------------------------------------------------------------
Describe 'C2C run-all - confirm-word gate' {

    It '(c) REJECTS the run when the confirm word is not exactly FIX (nothing changed)' {
        $plan = '[{"host":"RC1","pillars":["AntiMalware"]}]'
        $out = Invoke-C2cRunAll -Plan $plan -Confirm 'nope'
        $out.Result.summary.rejected | Should Be $true
        @($out.Rows).Count | Should Be 0
    }
}

# -----------------------------------------------------------------------------
Describe 'C2C run-all - self-guard drops the dispatcher host from the plan' {

    It '(d) drops the dispatcher host with a SKIPPED self-guard row and never fans out' {
        $plan = ('[{"host":"' + $env:COMPUTERNAME + '","pillars":["AntiMalware"]}]')
        $out = Invoke-C2cRunAll -Plan $plan
        $skips = @($out.Rows | Where-Object { $_.Status -eq 'SKIPPED' -and $_.Detail -match 'self-guard' })
        $skips.Count | Should Not Be 0
        $out.Result.summary.selfSkipped | Should Not Be 0
        $out.Result.summary.total | Should Be 0
    }
}

# -----------------------------------------------------------------------------
Describe 'C2C run-all - per-host pillar isolation' {

    It '(e) a two-host plan dials host A with ONLY Encryption and host B with ONLY AntiMalware' {
        $plan = '[{"host":"HOSTA","pillars":["Encryption"]},{"host":"HOSTB","pillars":["AntiMalware"]}]'
        $out = Invoke-C2cRunAll -Plan $plan
        $a = @($out.Rows | Where-Object { $_.Host -eq 'HOSTA' -and $_.Status -eq 'FIXED' })[0]
        $b = @($out.Rows | Where-Object { $_.Host -eq 'HOSTB' -and $_.Status -eq 'FIXED' })[0]
        $a | Should Not BeNullOrEmpty
        $b | Should Not BeNullOrEmpty
        $a.Detail | Should Be 'PILLARS=Encryption'
        $b.Detail | Should Be 'PILLARS=AntiMalware'
        $a.Detail | Should Not Match 'AntiMalware'
        $b.Detail | Should Not Match 'Encryption'
    }
}

# -----------------------------------------------------------------------------
Describe 'C2C label map - pillar-flavoured result labels' {

    It '(f) Monitoring already Running -> ALREADY MONITORED (raw NOCHANGE preserved)' {
        $r = Invoke-C2cMonitoring -Scenario 'healthy'
        $r.MonResult | Should Be 'NOCHANGE'            # raw token unchanged (rollup-stable)
        $r.Detail    | Should Match 'ALREADY MONITORED'
        $r.Report    | Should Match 'ALREADY MONITORED'
    }

    It '(f) Monitoring healed (Stopped -> started) -> MONITORED (raw FIXED preserved)' {
        $r = Invoke-C2cMonitoring -Scenario 'healed'
        $r.MonResult | Should Be 'FIXED'               # raw token unchanged (rollup-stable)
        $r.Detail    | Should Match 'MONITORED'
        $r.Detail    | Should Not Match 'ALREADY'
        $r.Status    | Should Be 'FIXED'
    }
}

# -----------------------------------------------------------------------------
Describe 'C2C Monitoring - Tanium installed-software + service matrix (fix-monitoring)' {

    It '(a) installed + service Running -> NOCHANGE MONITORED; detail notes installed + running' {
        $r = Invoke-C2cMonitoring -Scenario 'healthy'
        $r.MonResult | Should Be 'NOCHANGE'
        $r.MonDetail | Should Match '(?i)Tanium installed'
        $r.MonDetail | Should Match '(?i)already Running'
    }

    It '(b) installed + service Stopped -> heal starts it -> FIXED MONITORED' {
        $r = Invoke-C2cMonitoring -Scenario 'healed'
        $r.MonResult | Should Be 'FIXED'
        $r.MonDetail | Should Match '(?i)Tanium installed'
        $r.MonDetail | Should Match '(?i)healed'
    }

    It '(c) NOT installed + service absent -> FAIL, deploy from Software Center/MECM' {
        $r = Invoke-C2cMonitoring -Scenario 'notinstalled'
        $r.MonResult | Should Be 'FAIL'
        $r.MonDetail | Should Match '(?i)not installed'
        $r.MonDetail | Should Match '(?i)deploy from Software Center'
    }

    It '(d) installed + service ABSENT -> FAIL, repair via Software Center/MECM (no service created)' {
        $r = Invoke-C2cMonitoring -Scenario 'svcabsent'
        $r.MonResult | Should Be 'FAIL'
        $r.MonDetail | Should Match '(?i)Tanium installed'
        $r.MonDetail | Should Match '(?i)repair via Software Center'
    }
}

# -----------------------------------------------------------------------------
Describe 'C2C Monitoring - read-only scan check #1 (installed AND service running)' {

    It '(a) installed + service Running -> scan PASS, detail states BOTH facts' {
        $r = Invoke-C2cScanMonitoring -Scenario 'installedRunning'
        $r.MonStatus | Should Be 'PASS'
        $r.MonDetail | Should Match '(?i)Tanium installed'
        $r.MonDetail | Should Match '(?i)service Running'
    }

    It '(c) NOT installed + service absent -> scan FAIL, detail states BOTH facts' {
        $r = Invoke-C2cScanMonitoring -Scenario 'notinstalled'
        $r.MonStatus | Should Be 'FAIL'
        $r.MonDetail | Should Match '(?i)not installed'
        $r.MonDetail | Should Match '(?i)service not installed'
    }
}

# -----------------------------------------------------------------------------
Describe 'C2C run-all manifest - every input the view posts and the engine reads is DECLARED (audit 2026-07-24)' {

    # The view's RUN ALL always posts prunePki + fixRdp (the PkiRoots card boxes) and
    # Invoke-C2cFixAction reads both via Get-C2cBool, but the run-all manifest declared
    # neither - an undeclared input is invisible to every manifest-driven surface. Pin the
    # whole posted set so a future input cannot drift out of the manifest again.
    $ra = @(@((& $cm { Get-JanetToolManifest }).actions) | Where-Object { $_.id -eq 'run-all' })[0]
    $names = @(@($ra.inputs) | ForEach-Object { [string]$_.name })

    It 'declares the run-all action' { $ra | Should Not BeNullOrEmpty }
    It 'declares prunePki (bool, default OFF) - the expired-intermediate prune companion' {
        ($names -contains 'prunePki') | Should Be $true
        $i = @(@($ra.inputs) | Where-Object { $_.name -eq 'prunePki' })[0]
        [string]$i.type     | Should Be 'bool'
        [bool]$i.default    | Should Be $false
    }
    It 'declares fixRdp (bool, default OFF) - the broken-RDP-listener rebind companion' {
        ($names -contains 'fixRdp') | Should Be $true
        $i = @(@($ra.inputs) | Where-Object { $_.name -eq 'fixRdp' })[0]
        [string]$i.type     | Should Be 'bool'
        [bool]$i.default    | Should Be $false
    }
    It 'still declares the rest of the posted set (plan/csvPath/enableEncryption/certBundleFolder/confirm/winrmHeal/threads/attemptOffline)' {
        foreach ($n in @('plan','csvPath','enableEncryption','certBundleFolder','confirm','winrmHeal','threads','attemptOffline')) {
            ($names -contains $n) | Should Be $true
        }
    }
}

Describe 'c2c 1.16.0 - run-all prunePki/fixRdp/pushDisallowed declaration + the AntiMalware unreadable-sig fail-close' {
    # audit 2026-07-25 (fable re-audit follow-up): 1.15.13 -> 1.16.0 (trust-anchor guard on the
    # fix-pki push, the pushDisallowed distrust gate, the IN PROGRESS rollup state, the Java label).
    It 'manifest version is exactly 1.16.0 (newest bump holds the exact pin)' {
        $man = & $cm { Get-JanetToolManifest }
        [string]$man.version | Should Be '1.16.0'
    }
    It 'run-all declares pushDisallowed as a bool input defaulting to OFF (parity with fix-pki / certdeploy)' {
        $man = & $cm { Get-JanetToolManifest }
        $ra  = @($man.actions | Where-Object { $_.id -eq 'run-all' })[0]
        $pd  = @($ra.inputs | Where-Object { $_.name -eq 'pushDisallowed' })[0]
        $pd            | Should Not BeNullOrEmpty
        $pd.type       | Should Be 'bool'
        [bool]$pd.default | Should Be $false
    }
}

# -----------------------------------------------------------------------------
Describe 'C2C Tanium-installed probe - the single-source uninstall-registry helper' {

    # Dot-source the shared source string (the exact text both call sites run) and
    # shim Get-ItemProperty so the 64- and 32-bit uninstall-key scan is deterministic.
    function Invoke-C2cInstalledProbe {
        param([bool]$Installed, [string]$DisplayName = 'Tanium Client', [string]$Version = '7.4.5')
        & $cm {
            param($Installed, $DisplayName, $Version)
            $script:__inst = $Installed; $script:__dn = $DisplayName; $script:__ver = $Version
            $__shims = Save-ShimState @('Get-ItemProperty')
            function script:Get-ItemProperty {
                param($Path, $LiteralPath, $ErrorAction)
                if ($script:__inst) { return [pscustomobject]@{ DisplayName = $script:__dn; DisplayVersion = $script:__ver } }
                return @()
            }
            try {
                . ([scriptblock]::Create($script:C2cTaniumInstalledSrc))
                Get-C2cTaniumInstalled
            } finally {
                # audit 2026-07-25: this teardown was 'Remove-Item function:script:<name>' - an INERT path
                # (the function provider has no scope qualifier), so the shims leaked. See Add-ShimGuard above.
                Restore-ShimState $__shims
            }
        } $Installed $DisplayName $Version
    }

    It 'reports Installed = $true with the DisplayName + Version when a Tanium uninstall entry exists' {
        $p = Invoke-C2cInstalledProbe -Installed $true -Version '7.4.5.99'
        [bool]$p.Installed | Should Be $true
        $p.Version         | Should Be '7.4.5.99'
        $p.DisplayName     | Should Match '(?i)Tanium'
    }

    It 'reports Installed = $false when no uninstall entry matches Tanium' {
        $p = Invoke-C2cInstalledProbe -Installed $false
        [bool]$p.Installed | Should Be $false
    }

    It 'matches ONLY a DisplayName containing Tanium (a non-Tanium entry is not a match)' {
        $p = Invoke-C2cInstalledProbe -Installed $true -DisplayName 'Some Other App'
        [bool]$p.Installed | Should Be $false
    }
}
