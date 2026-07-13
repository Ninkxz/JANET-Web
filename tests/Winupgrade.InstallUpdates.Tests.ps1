# =============================================================================
#  Winupgrade.InstallUpdates.Tests.ps1 - Pester 3.4 tests for the DESTRUCTIVE
#  'install-updates' action on JanetWeb.winupgrade.psm1.
#
#  install-updates ports the HTTPS_Installer.ps1 engine: register a JANET_WUA
#  SYSTEM scheduled task running the WUA driver, poll C:\ProgramData\JANET\WUA\
#  result.json over a transport cascade (WinRM HTTPS 5986 -> WinRM HTTP 5985 ->
#  WMI/DCOM). This needs a live domain / WSUS ring to truly validate, so the
#  install path is SHIMMED here - NO real WinRM / WMI / scheduled task ever runs.
#
#  Coverage:
#   (1) manifest exposes install-updates destructive=$true with the exact confirm
#       string + the documented inputs and columns.
#   (2) SELF-GUARD: a self-only target list -> total=0, no fan-out, Self-guard warn
#       (the InstallUpdates op MUST drop the dispatcher host before dispatch, since
#       it installs updates + can force a reboot).
#   (3) the PURE Get-WinUpgradeWuaResultRow round-trips a result.json object through
#       ConvertTo/From-Json into a row, asserting the ResultCode->Status mapping
#       (2=Installed, 3=InstalledWithErrors, else InstallFailed; NoUpdates verbatim).
#   (4) the REAL per-host worker is driven DIRECTLY with Invoke-Command SHADOWED to
#       return canned result.json text - proving the transport path surfaces a
#       NoUpdates row and an Installed(+reboot) row. Never fakes a success.
#
#  Run:  Invoke-Pester -Path .\tests\Winupgrade.InstallUpdates.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.winupgrade.psm1') -Force -PassThru

$script:ExpectedConfirm = 'Install ALL available Windows Updates on the target(s) via a SYSTEM scheduled task (WSUS + optionally Microsoft Update)? This INSTALLS updates and some will force a REBOOT. The dispatcher host is skipped. Proceed?'

Describe 'winupgrade manifest exposes the destructive install-updates action' {
    $mani = & $m { Get-JanetToolManifest }
    $act  = $mani.actions | Where-Object { $_.id -eq 'install-updates' }

    It 'install-updates is present, stream-table, destructive=true, with a confirm' {
        $act | Should Not BeNullOrEmpty
        $act.kind | Should Be 'stream-table'
        $act.destructive | Should Be $true
        [string]$act.confirm | Should Not BeNullOrEmpty
    }
    It 'carries the exact confirm string from the design' {
        [string]$act.confirm | Should Be $script:ExpectedConfirm
    }
    It 'carries the documented inputs' {
        $names = @($act.inputs | ForEach-Object { $_.name })
        foreach ($n in 'targets','includeMU','allowHttp','allowWmi','timeoutMin','attemptOffline','dryRun','threads') {
            ($names -contains $n) | Should Be $true
        }
    }
    It 'includeMU / allowHttp / allowWmi default ON; timeoutMin defaults 45' {
        ($act.inputs | Where-Object { $_.name -eq 'includeMU' }).default  | Should Be $true
        ($act.inputs | Where-Object { $_.name -eq 'allowHttp' }).default  | Should Be $true
        ($act.inputs | Where-Object { $_.name -eq 'allowWmi' }).default   | Should Be $true
        [int]($act.inputs | Where-Object { $_.name -eq 'timeoutMin' }).default | Should Be 45
    }
    It 'exposes the install row columns' {
        foreach ($c in 'Host','Online','Transport','Method','Status','KBs','Reboot','Error') {
            ($act.columns -contains $c) | Should Be $true
        }
    }
}

Describe 'install-updates SELF-GUARD drops the dispatcher host before dispatch' {
    $ev = New-Object System.Collections.ArrayList
    $emit = { param($e) [void]$ev.Add($e) }
    $res = & $m {
        param($prm, $em)
        Invoke-JanetToolAction -ActionId 'install-updates' -Params $prm -Credential $null -Emit $em
    } @{ targets = '127.0.0.1' } $emit

    It 'returns total=0 with selfSkipped=1 and no rows (self was the only target)' {
        [int]$res.summary.total       | Should Be 0
        [int]$res.summary.selfSkipped | Should Be 1
        @($res.rows).Count            | Should Be 0
    }
    It 'emits a Self-guard warning and NEVER starts a dispatch' {
        $warn = $ev | Where-Object { $_.type -eq 'log' -and $_.level -eq 'warn' -and $_.text -match 'Self-guard' }
        $warn | Should Not BeNullOrEmpty
        $starting = $ev | Where-Object { $_.type -eq 'status' -and $_.text -match 'Starting' }
        $starting | Should BeNullOrEmpty
    }
}

Describe 'Get-WinUpgradeWuaResultRow - result.json -> row (ResultCode->Status mapping)' {

    # Round-trip through ConvertTo-Json | ConvertFrom-Json so we test exactly what the
    # worker's poll sees (result.json text parsed back into an object).
    function Shape([object]$obj) {
        $rt = $obj | ConvertTo-Json | ConvertFrom-Json
        return & $m { param($x) Get-WinUpgradeWuaResultRow -Result $x } $rt
    }

    It 'NoUpdates result -> Status NoUpdates, Ok, no reboot' {
        $row = Shape ([pscustomobject]@{ Status='NoUpdates'; Installed=0; Reboot=$false; KBs=@() })
        $row.Status | Should Be 'NoUpdates'
        [bool]$row.Ok     | Should Be $true
        [bool]$row.Reboot | Should Be $false
    }

    It 'ResultCode 2 -> Installed (+reboot, KBs joined), Ok' {
        $row = Shape ([pscustomobject]@{ Status='Installed'; ResultCode=2; Installed=2; Reboot=$true; KBs=@('KB5054156','KB5011048') })
        $row.Status | Should Be 'Installed'
        [bool]$row.Reboot | Should Be $true
        $row.KBs    | Should Match 'KB5054156'
        [bool]$row.Ok     | Should Be $true
    }

    It 'ResultCode 3 -> InstalledWithErrors, still Ok' {
        $row = Shape ([pscustomobject]@{ Status='InstalledWithErrors'; ResultCode=3; Reboot=$false; KBs=@() })
        $row.Status | Should Be 'InstalledWithErrors'
        [bool]$row.Ok | Should Be $true
    }

    It 'ResultCode 4 -> InstallFailed, NOT Ok (never faked as success)' {
        $row = Shape ([pscustomobject]@{ Status='InstallFailed'; ResultCode=4; Reboot=$false; KBs=@() })
        $row.Status | Should Be 'InstallFailed'
        [bool]$row.Ok | Should Be $false
        $row.Error  | Should Match '4'
    }

    It 'Error result -> Status Error, message surfaced, NOT Ok' {
        $row = Shape ([pscustomobject]@{ Status='Error'; Message='COM 0x80240438' })
        $row.Status | Should Be 'Error'
        [bool]$row.Ok | Should Be $false
        $row.Error  | Should Match '80240438'
    }

    It 'a $null result (no result.json before deadline) -> Timeout, Got=false, NOT Ok' {
        $row = & $m { Get-WinUpgradeWuaResultRow -Result $null }
        $row.Status | Should Be 'Timeout'
        [bool]$row.Got | Should Be $false
        [bool]$row.Ok  | Should Be $false
    }

    It 'nonce MISMATCH -> rejected: Got=false, NOT Ok (a stale Installed never surfaces)' {
        $rt = ([pscustomobject]@{ Status='Installed'; ResultCode=2; Reboot=$true; KBs=@('KB1'); Nonce='OLD'; Host='WS-A' }) | ConvertTo-Json | ConvertFrom-Json
        $row = & $m { param($x) Get-WinUpgradeWuaResultRow -Result $x -ExpectNonce 'NEW' -TargetShort 'WS-A' } $rt
        [bool]$row.Got | Should Be $false
        [bool]$row.Ok  | Should Be $false
        $row.Status    | Should Not Be 'Installed'
    }

    It 'matching nonce + matching Host -> the mapped Installed row (Got, Ok)' {
        $rt = ([pscustomobject]@{ Status='Installed'; ResultCode=2; Reboot=$true; KBs=@('KB1'); Nonce='NEW'; Host='WS-A.contoso.com' }) | ConvertTo-Json | ConvertFrom-Json
        $row = & $m { param($x) Get-WinUpgradeWuaResultRow -Result $x -ExpectNonce 'NEW' -TargetShort 'WS-A' } $rt
        $row.Status    | Should Be 'Installed'
        [bool]$row.Ok  | Should Be $true
    }

    It 'matching nonce but WRONG Host -> WrongBox, NOT Ok' {
        $rt = ([pscustomobject]@{ Status='Installed'; ResultCode=2; Nonce='NEW'; Host='WS-OTHER' }) | ConvertTo-Json | ConvertFrom-Json
        $row = & $m { param($x) Get-WinUpgradeWuaResultRow -Result $x -ExpectNonce 'NEW' -TargetShort 'WS-A' } $rt
        $row.Status    | Should Be 'WrongBox'
        [bool]$row.Ok  | Should Be $false
    }

    It 'IP-literal target -> host gate skipped (no false WrongBox on an IP dial)' {
        $rt = ([pscustomobject]@{ Status='NoUpdates'; Nonce='NEW'; Host='WS-REALNAME' }) | ConvertTo-Json | ConvertFrom-Json
        $row = & $m { param($x) Get-WinUpgradeWuaResultRow -Result $x -ExpectNonce 'NEW' -TargetShort '10' -TargetIsIp $true } $rt
        $row.Status    | Should Be 'NoUpdates'
        [bool]$row.Ok  | Should Be $true
    }
}

Describe 'install-updates worker end to end (shimmed transport/poll - no real WinRM/WMI/task)' {

    # Drive the REAL worker directly with Invoke-Command shadowed to return canned
    # result.json TEXT (what the in-session task runner returns). AttemptOffline is
    # forced $true so the worker proceeds past the fake-host reachability probe into
    # the transport cascade; the first (HTTPS 5986) attempt is served the canned json.
    #  The shim mirrors the REAL SYSTEM driver: the driver stamps its OWN nonce (the one
    #  the worker baked in via #__NONCE__#, handed to the runner as ArgumentList[2]) and
    #  Host=$env:COMPUTERNAME into result.json. So by default the shim stamps Nonce =
    #  ArgumentList[2] (matches this run) and Host = the dialed ComputerName (correct box).
    #  NonceOverride / HostOverride simulate a stale-nonce (wrong-run) or wrong-box read.
    function Invoke-InstallWorker {
        param([string]$Computer, [string]$ResultJson, [bool]$DryRun = $false,
              [bool]$AllowHttp = $true, [bool]$AllowWmi = $true,
              $NonceOverride = $null, $HostOverride = $null, [bool]$Stamp = $true)
        return & $m {
            param($Computer, $ResultJson, $DryRun, $AllowHttp, $AllowWmi, $NonceOverride, $HostOverride, $Stamp)
            Set-Variable -Name __json    -Scope script -Value $ResultJson
            Set-Variable -Name __calls   -Scope script -Value (New-Object System.Collections.ArrayList)
            Set-Variable -Name __stamp   -Scope script -Value $Stamp
            Set-Variable -Name __nonceOv -Scope script -Value $NonceOverride
            Set-Variable -Name __hostOv  -Scope script -Value $HostOverride
            function script:Invoke-Command {
                param($ComputerName,$ScriptBlock,$ArgumentList,$Authentication,$SessionOption,$ErrorAction,$Credential,$Session,$Port,$UseSSL)
                $t = [string]$ScriptBlock
                if ($t -match 'Register-ScheduledTask' -or $t -match 'result\.json') {
                    [void]$script:__calls.Add('RUN')
                    $json = $script:__json
                    if ($script:__stamp) {
                        $n = if ($null -ne $script:__nonceOv) { $script:__nonceOv } else { $ArgumentList[2] }
                        $h = if ($null -ne $script:__hostOv)  { $script:__hostOv }  else { $ComputerName }
                        try {
                            $obj = $json | ConvertFrom-Json
                            $obj | Add-Member -NotePropertyName Nonce -NotePropertyValue $n -Force
                            $obj | Add-Member -NotePropertyName Host  -NotePropertyValue $h -Force
                            $json = $obj | ConvertTo-Json
                        } catch {}
                    }
                    return $json
                }
                return $null
            }
            try {
                $argl = @(
                    $Computer,'InstallUpdates',$null,'Windows 11','24H2',
                    '','',$false,$false,$true,
                    $DryRun,$false,16384,$null,$null,
                    $false,$false,$false,$true,'x',
                    4,64,'2.0','y',$false,
                    300,$null,26100,$false,$false,
                    $false,$false,$false,$false,$false,
                    $true,$AllowHttp,$AllowWmi,45,'DRV|MU=#__INCLUDEMU__#|N=#__NONCE__#'
                )
                $row = & $script:WinUpgradeWorker @argl
                return @{ Row = $row; Calls = @($script:__calls) }
            } finally {
                Remove-Item function:script:Invoke-Command -ErrorAction SilentlyContinue
                Remove-Variable -Name __json,__calls,__stamp,__nonceOv,__hostOv -Scope script -ErrorAction SilentlyContinue
            }
        } $Computer $ResultJson $DryRun $AllowHttp $AllowWmi $NonceOverride $HostOverride $Stamp
    }

    It 'a NoUpdates result.json -> Status NoUpdates over the HTTPS transport, no reboot' {
        $out = Invoke-InstallWorker -Computer 'WS-NOUPD' -ResultJson '{"Status":"NoUpdates","Reboot":false,"KBs":[]}'
        ($out.Calls -contains 'RUN') | Should Be $true
        $out.Row.Status    | Should Be 'NoUpdates'
        $out.Row.Transport | Should Be 'HTTPS'
        $out.Row.Method    | Should Be 'SchedTask(SYSTEM)'
        [bool]$out.Row.Reboot | Should Be $false
        [bool]$out.Row.Ok     | Should Be $true
    }

    It 'an Installed(+reboot) result.json -> Status Installed, Reboot true, KBs surfaced' {
        $out = Invoke-InstallWorker -Computer 'WS-INST' -ResultJson '{"Status":"Installed","ResultCode":2,"Installed":1,"Reboot":true,"KBs":["KB5054156"]}'
        $out.Row.Status    | Should Be 'Installed'
        [bool]$out.Row.Reboot | Should Be $true
        $out.Row.KBs       | Should Match 'KB5054156'
        [bool]$out.Row.Ok  | Should Be $true
    }

    It 'an InstallFailed (ResultCode 4) result.json -> Status InstallFailed, NOT Ok (never faked)' {
        $out = Invoke-InstallWorker -Computer 'WS-FAIL' -ResultJson '{"Status":"InstallFailed","ResultCode":4,"Reboot":false,"KBs":[]}'
        $out.Row.Status   | Should Be 'InstallFailed'
        [bool]$out.Row.Ok | Should Be $false
    }

    It 'matching nonce + matching Host -> the mapped Installed row (happy path proven)' {
        $out = Invoke-InstallWorker -Computer 'WS-OK' -ResultJson '{"Status":"Installed","ResultCode":2,"Reboot":false,"KBs":["KB5054156"]}'
        ($out.Calls -contains 'RUN') | Should Be $true
        $out.Row.Status   | Should Be 'Installed'
        [bool]$out.Row.Ok | Should Be $true
    }

    It 'a WRONG-nonce result.json is REJECTED - never surfaces as Installed (stale/prior run)' {
        # The driver ran (RUN recorded) but stamped a stale nonce -> the worker must reject it
        # and keep polling; with no other transport it ends NOT Ok and NOT a success status.
        $out = Invoke-InstallWorker -Computer 'WS-STALE' `
                 -ResultJson '{"Status":"Installed","ResultCode":2,"Reboot":true,"KBs":["KB9999999"]}' `
                 -NonceOverride 'deadbeefdeadbeefdeadbeefdeadbeef' -AllowHttp $false -AllowWmi $false
        ($out.Calls -contains 'RUN')   | Should Be $true
        [bool]$out.Row.Ok              | Should Be $false
        @('Installed','InstalledWithErrors','NoUpdates') -contains $out.Row.Status | Should Be $false
    }

    It 'a Host-mismatch result.json -> WrongBox row, NOT Ok (wrong box, stale DNS / reused IP)' {
        $out = Invoke-InstallWorker -Computer 'WS-INTENDED' `
                 -ResultJson '{"Status":"Installed","ResultCode":2,"Reboot":false,"KBs":["KB5054156"]}' `
                 -HostOverride 'WS-OTHERBOX'
        $out.Row.Status   | Should Be 'WrongBox'
        [bool]$out.Row.Ok | Should Be $false
        $out.Row.Error    | Should Match 'WRONG BOX'
    }

    It 'Dry-run -> DRY-RUN row and NO SYSTEM task ever registered (no RUN call)' {
        $out = Invoke-InstallWorker -Computer 'WS-DRY' -ResultJson '{"Status":"NoUpdates"}' -DryRun $true
        ($out.Calls -contains 'RUN') | Should Be $false
        $out.Row.Status | Should Be 'DRY-RUN'
        $out.Row.Detail | Should Match 'Would register'
    }
}
