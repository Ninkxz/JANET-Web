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
$cm = Import-Module (Join-Path $script:Root 'modules\JanetWeb.c2c.psm1') -Force -PassThru

# Run the 'run-all' action with the per-host worker swapped for an ECHO shim that
# reports the EXACT pillar set each host was dialed with (Detail 'PILLARS=a+b').
function Invoke-C2cRunAll {
    param([string]$Plan, [string]$Confirm = 'FIX', [string]$SstPath = '', [bool]$Enable = $false, [bool]$Shim = $true)
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
                param([string]$Computer, $Cred, [string]$Auth, [bool]$AttemptOffline, [string[]]$Pillars, [bool]$DoEnable, [string]$SstB64, [string]$TaniumService)
                $ps = @(@($Pillars) | ForEach-Object { [string]$_ })
                @{ Host = $Computer; Ping = 'shim'; Status = 'FIXED'; Detail = ('PILLARS=' + ($ps -join '+'));
                   Report = ''; Pillars = @($ps | ForEach-Object { [pscustomobject]@{ Name = $_; Action = 'shim'; Result = 'FIXED'; Detail = 'shim' } }) }
            }
        }
    }
    try {
        $params = @{ plan = $Plan; confirm = $Confirm; attemptOffline = $true; threads = 4 }
        if ($SstPath) { $params['sstPath'] = $SstPath }
        if ($Enable)  { $params['enableEncryption'] = $true }
        $res = Invoke-JanetToolAction -ActionId 'run-all' -Params $params -Credential $null -Emit $emit
    } finally {
        if ($Shim) { & $cm { $script:C2cFixBlock = $script:__origFixBlock; Remove-Variable -Name __origFixBlock -Scope Script -ErrorAction SilentlyContinue } }
    }
    [pscustomobject]@{ Result = $res; Rows = @($script:__rows); Logs = @($script:__logs) }
}

# Run the REAL Monitoring fixer LOCALLY (Enable-test shim idiom) so the pillar
# label map is exercised end-to-end. $Scenario: 'healthy' (already Running) or
# 'healed' (Stopped/Manual -> started + Automatic).
function Invoke-C2cMonitoring {
    param([string]$Scenario)
    & $cm {
        param($Scenario)
        function script:New-PSSession { param($ComputerName, $SessionOption, $Authentication, $ErrorAction, $Credential) [pscustomobject]@{ Id = 1; Name = 'shim' } }
        function script:Remove-PSSession { param($Session, $ErrorAction) }
        function script:Invoke-Command {
            param($Session, $ComputerName, $ScriptBlock, $ArgumentList, $ErrorAction, $Credential, $Authentication, $SessionOption)
            if ($ScriptBlock -and ($ScriptBlock.ToString().Trim() -eq '$env:COMPUTERNAME')) { return $env:COMPUTERNAME }
            return (& $ScriptBlock @ArgumentList)
        }
        $script:__svcCalls = 0
        $script:__scn = $Scenario
        function script:Get-Service {
            param($Name, $ErrorAction)
            $script:__svcCalls++
            if ($script:__scn -eq 'healthy') { return [pscustomobject]@{ Name = $Name; Status = 'Running'; StartType = 'Automatic' } }
            if ($script:__svcCalls -le 1)    { return [pscustomobject]@{ Name = $Name; Status = 'Stopped'; StartType = 'Manual' } }
            return [pscustomobject]@{ Name = $Name; Status = 'Running'; StartType = 'Automatic' }
        }
        function script:Set-Service { param($Name, $StartupType, $ErrorAction) }
        function script:Start-Service { param($Name, $ErrorAction) }
        try {
            # target = self so the wrong-box guard passes; Pillars = Monitoring only.
            $res = & $script:C2cFixBlock $env:COMPUTERNAME $null 'Default' $true @('Monitoring') $false '' 'Tanium Client'
            $mon = @(@($res.Pillars) | Where-Object { $_.Name -eq 'Monitoring' })[0]
            [pscustomobject]@{
                Status    = [string]$res.Status
                Detail    = [string]$res.Detail
                Report    = [string]$res.Report
                MonResult = $(if ($mon) { [string]$mon.Result } else { '' })
            }
        } finally {
            Remove-Item function:script:New-PSSession, function:script:Remove-PSSession, function:script:Invoke-Command, `
                function:script:Get-Service, function:script:Set-Service, function:script:Start-Service -ErrorAction SilentlyContinue
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
Describe 'C2C run-all - PkiRoots planned without a .sst aborts before any host' {

    It '(b) aborts the whole run (nothing dialed) with a clear PKI error' {
        $plan = '[{"host":"RB1","pillars":["PkiRoots"]},{"host":"RB2","pillars":["AntiMalware"]}]'
        $out = Invoke-C2cRunAll -Plan $plan   # no sstPath
        $out.Result.summary.rejected | Should Be $true
        @($out.Rows | Where-Object { $_.Status -eq 'FIXED' }).Count | Should Be 0
        @($out.Logs | Where-Object { $_.level -eq 'err' -and $_.text -match 'PkiRoots' -and $_.text -match 'ABORTED' }).Count | Should Not Be 0
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
