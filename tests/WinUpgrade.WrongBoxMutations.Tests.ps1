# =============================================================================
#  WinUpgrade.WrongBoxMutations.Tests.ps1 - Pester 3.4 tests for the wrong-box
#  residuals found by the fable re-audit (audit 2026-07-25 (fable re-audit
#  follow-up)) on JanetWeb.winupgrade.psm1.
#
#  The v0.5.7 pass put a $env:COMPUTERNAME guard on the INSTALL step of every
#  destructive path, but three blocks still MUTATED a mis-resolved host before
#  that guard could fire:
#
#    1. InstallCab created C:\Temp and pushed the (multi-GB) feature-update
#       package onto whatever box answered - only DISM itself was guarded.
#    2. The install-updates WMI/DCOM bootstrap created %ProgramData%\JANET\WUA
#       and DELETED result.json before its $exp check, so a wrongly-reached host
#       lost the result of a CONCURRENT legitimate install-updates run.
#    3. The WMI/DCOM cleanup bootstrap was UNGUARDED entirely - it unregistered
#       the JANET_WUA SYSTEM task on whatever box answered, which kills a
#       concurrent legitimate run on that host.
#
#  These are BEHAVIOURAL: each guarded block is invoked LOCALLY with a machine
#  name this box is NOT, and the assertion is that the mutation never happened
#  (no directory created, no copy attempted, no file deleted, no task
#  unregistered) - not that some string appears in the source.
#
#  Nothing here touches a real host: the block roots are redirected into a temp
#  directory and every mismatch case returns BEFORE any destructive call, so
#  Register/Unregister-ScheduledTask are never reached.
#
#  Run:  Invoke-Pester -Path .\tests\WinUpgrade.WrongBoxMutations.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent
$m = Import-Module (Join-Path $script:Root 'modules\JanetWeb.winupgrade.psm1') -Force -PassThru

# A name this machine can never be (the guard compares against $env:COMPUTERNAME).
$script:NotThisBox = 'WS-NOT-THIS-BOX-' + ([guid]::NewGuid().ToString('N').Substring(0, 8))

function New-TempRoot {
    $p = Join-Path ([IO.Path]::GetTempPath()) ('jwup_' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $p -Force | Out-Null
    return $p
}

Describe 'InstallCab staging aborts on the WRONG BOX before the CAB directory exists (audit 2026-07-25)' {

    $stageSb = & $m { $script:WinUpgradeCabStageBlock }

    It 'the shared staging block is threaded to the worker (it exists at module scope)' {
        $stageSb | Should Not BeNullOrEmpty
    }

    It 'a mismatched machine name -> NOT Ok and the staging directory is NEVER created' {
        $tmp  = New-TempRoot
        $root = Join-Path $tmp 'Temp'
        try {
            $out = & $stageSb $script:NotThisBox $root
            [bool]$out.Ok      | Should Be $false
            [bool]$out.Created | Should Be $false
            [string]$out.Error | Should Match 'DNS mismatch'
            (Test-Path -LiteralPath $root) | Should Be $false
        } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'the RIGHT box still stages (the guard refuses wrong boxes, it does not break staging)' {
        $tmp  = New-TempRoot
        $root = Join-Path $tmp 'Temp'
        try {
            $out = & $stageSb $env:COMPUTERNAME $root
            [bool]$out.Ok      | Should Be $true
            [bool]$out.Created | Should Be $true
            (Test-Path -LiteralPath $root) | Should Be $true
        } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'an empty expected name (IP-literal target) still stages - no false abort on an IP dial' {
        $tmp  = New-TempRoot
        $root = Join-Path $tmp 'Temp'
        try {
            $out = & $stageSb '' $root
            [bool]$out.Ok | Should Be $true
        } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'the InstallCab worker NEVER copies the package to a wrong box (audit 2026-07-25)' {

    # Drive the REAL worker with the session/transport shimmed inside module scope.
    # Invoke-Command EXECUTES the block locally, which is exactly the wrong-box case:
    # the machine that answered is THIS one, and the dialed name is not its name. A
    # Copy-Item shim records every push attempt without moving a byte.
    function Invoke-CabWorker {
        param([string]$Computer)
        return & $m {
            param($Computer)
            Set-Variable -Name __calls -Scope script -Value (New-Object System.Collections.ArrayList)
            function script:New-PSSession {
                [CmdletBinding()] param($ComputerName, $Authentication, $SessionOption, $Credential, $Port, [switch]$UseSSL)
                [pscustomobject]@{ Id = 1; ComputerName = $ComputerName }
            }
            function script:Remove-PSSession { [CmdletBinding()] param([Parameter(Position = 0)]$Session) }
            function script:Invoke-Command {
                param($Session, $ScriptBlock, $ArgumentList, $ComputerName, $Authentication, $SessionOption, $ErrorAction, $Credential, $Port, $UseSSL)
                [void]$script:__calls.Add('IC')
                if ($ArgumentList) { return & $ScriptBlock @ArgumentList }
                return & $ScriptBlock
            }
            function script:Copy-Item {
                param($Path, $Destination, $ToSession, $LiteralPath, [switch]$Force, $ErrorAction)
                [void]$script:__calls.Add('COPY')
            }
            try {
                $argl = @(
                    $Computer,'InstallCab',$null,'Windows 11','24H2',
                    'C:\packages\feature.cab','feature.cab',$false,$false,$true,
                    $false,$false,16384,$null,$null,
                    $false,$false,$false,$false,'x',
                    4,25,'2.0','y',$false,
                    300,$null,26100,$false,$false,
                    $false,$false,$false,$false,$false,
                    $true,$true,$true,45,'DRV'
                )
                $row = & $script:WinUpgradeWorker @argl
                return @{ Row = $row; Calls = @($script:__calls) }
            } finally {
                # Unqualified 'function:<name>' - 'function:script:<name>' does NOT resolve,
                # so that spelling leaves the shim in place for every later Describe.
                foreach ($fn in 'New-PSSession','Remove-PSSession','Invoke-Command','Copy-Item') {
                    Remove-Item -LiteralPath "function:$fn" -ErrorAction SilentlyContinue
                }
                Remove-Variable -Name __calls -Scope script -ErrorAction SilentlyContinue
            }
        } $Computer
    }

    $out = Invoke-CabWorker -Computer $script:NotThisBox

    It 'no Copy-Item is ever attempted once the box answers with a different name' {
        ($out.Calls -contains 'COPY') | Should Be $false
    }

    It 'the row FAILS with an explicit staging abort (never a silent success)' {
        $out.Row.Status   | Should Be 'FAILED'
        [bool]$out.Row.Ok | Should Be $false
        [string]$out.Row.Detail | Should Match 'ABORTED'
        [string]$out.Row.Detail | Should Match 'DNS mismatch'
    }
}

Describe 'the install-updates WMI/DCOM bootstrap aborts before it mutates a wrong box (audit 2026-07-25)' {

    $bootSb = & $m { $script:WinUpgradeWuaBootstrapBlock }

    It 'the shared bootstrap block is threaded to the worker (it exists at module scope)' {
        $bootSb | Should Not BeNullOrEmpty
    }

    It 'a mismatched machine name -> aborts, registers NOTHING and creates NO directory' {
        $tmp  = New-TempRoot
        $base = Join-Path (Join-Path $tmp 'JANET') 'WUA'
        try {
            $out = & $bootSb $script:NotThisBox 'nonce0123456789' 'QUJD' $base $tmp
            [bool]$out.Aborted    | Should Be $true
            [bool]$out.Registered | Should Be $false
            (Test-Path -LiteralPath $base) | Should Be $false
        } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'a CONCURRENT run''s result.json is neither deleted nor overwritten on the wrong box' {
        $tmp  = New-TempRoot
        $base = Join-Path (Join-Path $tmp 'JANET') 'WUA'
        New-Item -ItemType Directory -Path $base -Force | Out-Null
        $live = Join-Path $base 'result.json'
        Set-Content -LiteralPath $live -Value '{"Status":"Installed","Nonce":"OTHERRUN"}' -Encoding UTF8
        try {
            $out = & $bootSb $script:NotThisBox 'nonce0123456789' 'QUJD' $base $tmp
            [bool]$out.Aborted | Should Be $true
            (Test-Path -LiteralPath $live) | Should Be $true
            (Get-Content -LiteralPath $live -Raw) | Should Match 'OTHERRUN'
        } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'the WrongBox signal goes to a NONCE-named marker (it can collide with nothing)' {
        $tmp  = New-TempRoot
        $base = Join-Path (Join-Path $tmp 'JANET') 'WUA'
        try {
            $null = & $bootSb $script:NotThisBox 'nonce0123456789' 'QUJD' $base $tmp
            $marker = Join-Path $tmp 'JANET_WUA.wrongbox.nonce0123456789.json'
            (Test-Path -LiteralPath $marker) | Should Be $true
            $txt = Get-Content -LiteralPath $marker -Raw
            $txt | Should Match 'WrongBox'
            $txt | Should Match 'nonce0123456789'
        } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'that marker shapes into an explicit WrongBox row, NOT Ok (the poller reads it)' {
        $row = & $m {
            param($j) Get-WinUpgradeWuaResultRow -Result ($j | ConvertFrom-Json) -ExpectNonce 'nonce0123456789' -TargetShort 'WS-INTENDED'
        } ('{"Status":"WrongBox","Nonce":"nonce0123456789","Host":"WS-SOMEONE-ELSE"}')
        $row.Status   | Should Be 'WrongBox'
        [bool]$row.Ok | Should Be $false
    }
}

Describe 'the install-updates WMI/DCOM cleanup aborts on a wrong box (audit 2026-07-25)' {

    $cleanSb = & $m { $script:WinUpgradeWuaCleanupBlock }

    It 'the shared cleanup block is threaded to the worker (it exists at module scope)' {
        $cleanSb | Should Not BeNullOrEmpty
    }

    It 'a mismatched machine name -> NO task unregistered and NO file deleted' {
        $tmp = New-TempRoot
        $drv = Join-Path $tmp 'driver.ps1'
        $res = Join-Path $tmp 'result.json'
        Set-Content -LiteralPath $drv -Value '# concurrent run driver' -Encoding UTF8
        Set-Content -LiteralPath $res -Value '{"Status":"Installed","Nonce":"OTHERRUN"}' -Encoding UTF8
        try {
            $out = & $cleanSb $script:NotThisBox $tmp
            [bool]$out.Aborted      | Should Be $true
            [bool]$out.Unregistered | Should Be $false
            (Test-Path -LiteralPath $drv) | Should Be $true
            (Test-Path -LiteralPath $res) | Should Be $true
        } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'winupgrade manifest version' {
    It 'is 0.5.8 (wrong-box residual pass)' {
        (& $m { (Get-JanetToolManifest).version }) | Should Be '0.5.8'
    }
}
