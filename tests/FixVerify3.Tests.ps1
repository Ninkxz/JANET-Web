# =============================================================================
#  FixVerify3.Tests.ps1 - Pester 3.4 tests for the third wave of correctness+honesty
#  fixes. Each proves an additive change: no-op / soft-fail / indeterminate outcomes
#  are reported DISTINCTLY instead of being masked as a clean success, and the happy
#  path (a genuine change / clean run / confirmed bump) is unchanged.
#
#    FIX 1  DHCP single-scope Apply short-circuits an unchanged re-apply to NoChange
#           (no Set), instead of writing + auditing it as 'Changed'.
#    FIX 2  pkginstall PSADT run with a success exit but ERROR/FAILED output lines is
#           reported 'Success (warnings)', not a plain 'Success' with a footnote.
#    FIX 3  WinUpgrade Pin AND Unpin expose a non-empty destructive 'confirm' string.
#    FIX 4  Secure Boot: an already-staged (pending-reboot) enable does NOT re-fire the
#           OEM WMI write; a Dell no-change read-back reports pending reboot (not a clean
#           success); an unreadable state resolves to a distinct 'Unknown' status.
#    FIX 5  ACAS "version unchanged after update" is a distinct 'UNCONFIRMED' state that
#           AcasOkOf counts as NOT-OK; a confirmed version bump stays OK.
#
#  All engine calls are driven with the module's OWN remote/WMI seams shadowed IN
#  MODULE SCOPE (or the payload/worker source extracted via the PS parser and run
#  against shims). No live host is touched.
#
#  Run:  Invoke-Pester -Path .\tests\FixVerify3.Tests.ps1
# =============================================================================
$script:Root = Split-Path $PSScriptRoot -Parent

# -----------------------------------------------------------------------------
Describe 'FIX 1 - DHCP single-scope Apply no-ops an unchanged re-apply (JanetWeb.dhcp.psm1)' {

    $dm = Import-Module (Join-Path $script:Root 'modules\JanetWeb.dhcp.psm1') -Force -PassThru

    # Drive the REAL Invoke-JanetDhcpApply with the two remote seams shadowed:
    #   Invoke-JanetOnDhcp          -> the pre-read (returns canned current values)
    #   Invoke-JanetOnDhcpCancelable-> the WRITE (records that it was called)
    # so the function's real diff + short-circuit logic runs on synthetic data.
    function Invoke-DhcpApply {
        param([string[]]$Current, [string[]]$Desired, [bool]$ReadOk = $true)
        & $dm {
            param($Current, $Desired, $ReadOk)
            $script:__cur     = @($Current)
            $script:__readOk  = $ReadOk
            $script:__setCnt  = 0
            function script:Invoke-JanetOnDhcp {
                [CmdletBinding()] param($Server, $Script, $Arguments, $Credential)
                [pscustomobject]@{
                    Ok     = $script:__readOk
                    Values = $script:__cur
                    NotSet = ($script:__cur.Count -eq 0)
                    Err    = $(if (-not $script:__readOk) { 'simulated read failure' } else { $null })
                }
            }
            function script:Invoke-JanetOnDhcpCancelable {
                [CmdletBinding()] param($Server, $Script, $Arguments, $Credential, $CancelCheck)
                $script:__setCnt++
                [pscustomobject]@{ Cancelled = $false; Result = @([pscustomobject]@{ Removed = $false }) }
            }
            try {
                $send = { param($e) }
                $res = Invoke-JanetDhcpApply -Server 'TESTSRV' -ScopeId '10.0.0.0' -OptionId 6 `
                            -NewValues $Desired -Credential $null -Send $send
                [pscustomobject]@{
                    Status   = [string]$res.summary.status
                    Ok       = [int]$res.summary.ok
                    Failed   = [int]$res.summary.failed
                    SetCalls = [int]$script:__setCnt
                }
            } finally {
                Remove-Item function:script:Invoke-JanetOnDhcp, function:script:Invoke-JanetOnDhcpCancelable -EA SilentlyContinue
            }
        } $Current $Desired $ReadOk
    }

    It 'current == desired => NoChange and NO Set is issued (happy no-op)' {
        $r = Invoke-DhcpApply -Current @('10.0.0.1','10.0.0.2') -Desired @('10.0.0.1','10.0.0.2')
        $r.Status   | Should Be 'NoChange'
        $r.SetCalls | Should Be 0
        $r.Ok       | Should Be 1
        $r.Failed   | Should Be 0
    }
    It 'current != desired => the write IS issued and it reports Changed (happy path unchanged)' {
        $r = Invoke-DhcpApply -Current @('10.0.0.9') -Desired @('10.0.0.1','10.0.0.2')
        $r.Status   | Should Be 'Changed'
        $r.SetCalls | Should Be 1
        $r.Ok       | Should Be 1
    }
    It 'read ERROR => aborts (no false short-circuit, no Set)' {
        $r = Invoke-DhcpApply -Current @('10.0.0.1','10.0.0.2') -Desired @('10.0.0.1','10.0.0.2') -ReadOk $false
        $r.Status   | Should Be 'Error'
        $r.SetCalls | Should Be 0
        $r.Failed   | Should Be 1
    }
}

# -----------------------------------------------------------------------------
Describe 'FIX 2 - pkginstall PSADT soft-fail is Success (warnings) (JanetWeb.pkginstall.psm1)' {

    $pm = Import-Module (Join-Path $script:Root 'modules\JanetWeb.pkginstall.psm1') -Force -PassThru

    # Extract the inline "run Deploy-Application.ps1 + classify exit/output" scriptblock
    # from $script:RpiDeployHostScript via the PS parser, then run it against a REAL temp
    # package whose Deploy-Application.ps1 emits chosen output and exits success. This runs
    # the module's REAL exit/soft-fail classification.
    $rpi = & $pm { $script:RpiDeployHostScript }
    $sbe = $rpi.Ast.FindAll(
        { param($n) $n -is [System.Management.Automation.Language.ScriptBlockExpressionAst] -and
                    $n.Extent.Text -match 'successExits' -and $n.Extent.Text -match 'Deploy-Application\.ps1' },
        $true) | Select-Object -First 1
    $script:__deployBlock = & ([scriptblock]::Create($sbe.Extent.Text))

    function Invoke-Psadt {
        param([string]$DeployOutput)
        $pkg = Join-Path ([System.IO.Path]::GetTempPath()) ('psadt_' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $pkg -Force | Out-Null
        # No 'exit' -> $LASTEXITCODE stays at the 0 the block sets before invoking, so the
        # scenario is a SUCCESS exit code with (optionally) ERROR/FAILED output lines.
        $body = 'param($DeployMode)' + "`r`n" + $DeployOutput
        Set-Content -LiteralPath (Join-Path $pkg 'Deploy-Application.ps1') -Value $body -Encoding UTF8
        $loc = Get-Location
        try {
            $res = & $script:__deployBlock $pkg
            [pscustomobject]@{ Status = [string]$res.Status; Reason = [string]$res.Reason; ExitCode = $res.ExitCode }
        } finally {
            Set-Location $loc
            Remove-Item -LiteralPath $pkg -Recurse -Force -EA SilentlyContinue
        }
    }

    It 'success exit + ERROR line in output => Success (warnings), warning text surfaced' {
        $r = Invoke-Psadt -DeployOutput "Write-Output 'ERROR: component X failed to register'"
        $r.ExitCode | Should Be 0
        $r.Status   | Should Be 'Success (warnings)'
        $r.Reason   | Should Match 'WARNING'
        $r.Reason   | Should Match 'component X failed to register'
    }
    It 'success exit + FAILED line in output => Success (warnings)' {
        $r = Invoke-Psadt -DeployOutput "Write-Output 'FAILED to copy config'"
        $r.Status | Should Be 'Success (warnings)'
    }
    It 'clean output => plain Success (happy path unchanged)' {
        $r = Invoke-Psadt -DeployOutput "Write-Output 'Installation completed OK'"
        $r.Status | Should Be 'Success'
    }
}

# -----------------------------------------------------------------------------
Describe 'FIX 3 - WinUpgrade Pin AND Unpin expose a confirm string (JanetWeb.winupgrade.psm1)' {

    $wm = Import-Module (Join-Path $script:Root 'modules\JanetWeb.winupgrade.psm1') -Force -PassThru
    $man = & $wm { Get-JanetToolManifest }

    It 'pin is destructive AND has a non-empty confirm' {
        $pin = @($man.actions | Where-Object { $_.id -eq 'pin' })[0]
        $pin.destructive | Should Be $true
        $pin.confirm     | Should Not BeNullOrEmpty
        $pin.confirm     | Should Match 'Target Release Version'
    }
    It 'unpin is destructive AND has a non-empty confirm' {
        $unpin = @($man.actions | Where-Object { $_.id -eq 'unpin' })[0]
        $unpin.destructive | Should Be $true
        $unpin.confirm     | Should Not BeNullOrEmpty
        $unpin.confirm     | Should Match 'normal Windows Update'
    }
}

# -----------------------------------------------------------------------------
Describe 'FIX 4 - Secure Boot idempotency + honest state labels (JanetWeb.secureboot.psm1)' {

    $sbm = Import-Module (Join-Path $script:Root 'modules\JanetWeb.secureboot.psm1') -Force -PassThru

    # --- Dell OEM function extracted from the remote payload, run against shims. ---
    $payload = & $sbm { $script:SbePayload }
    $tk = $null; $er = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($payload, [ref]$tk, [ref]$er)
    $defs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                           ($n.Name -eq 'New-Result' -or $n.Name -eq 'Enable-DellSecureBoot') }, $true)
    $script:__dellSrc = ($defs | ForEach-Object { $_.Extent.Text }) -join "`n`n"

    function Invoke-Dell {
        param([string]$CurrentVal, [int]$SetStatus = 0)
        & {
            param($src, $CurrentVal, $SetStatus)
            $BIOSPassword       = 'pw'
            $script:__setCnt    = 0
            $script:__cur       = $CurrentVal
            $script:__setstatus = $SetStatus
            function Get-CimInstance {
                [CmdletBinding()] param($Namespace, $ClassName)
                [pscustomobject]@{ AttributeName = 'SecureBoot'; CurrentValue = $script:__cur }
            }
            function Get-WmiObject {
                [CmdletBinding()] param($Namespace, $Class)
                $o = [pscustomobject]@{}
                $o | Add-Member -MemberType ScriptMethod -Name SetAttribute -Value {
                    param($a, $b, $c, $d, $e) $script:__setCnt++; [pscustomobject]@{ Status = $script:__setstatus }
                }
                return $o
            }
            Invoke-Expression $src
            $res = Enable-DellSecureBoot
            [pscustomobject]@{ NewValue = [string]$res.NewValue; SetResult = [string]$res.SetResult; Error = [string]$res.Error; SetCalls = [int]$script:__setCnt }
        } $script:__dellSrc $CurrentVal $SetStatus
    }

    Context 'Idempotent re-run (enable already staged, pending reboot)' {
        It 'firmware config already Enabled => NO WMI write is re-fired, reports already pending reboot' {
            $r = Invoke-Dell -CurrentVal 'Enabled'
            $r.SetCalls | Should Be 0
            $r.NewValue | Should Match 'already pending reboot'
        }
    }
    Context 'Dell no-change read-back' {
        It 'write accepted but read-back unchanged => pending reboot (NOT a clean immediate success)' {
            $r = Invoke-Dell -CurrentVal 'Disabled' -SetStatus 0
            $r.SetCalls | Should Be 1
            $r.NewValue | Should Match 'pending reboot'
            $r.NewValue | Should Not Match 'no change detected'
            $r.Error    | Should BeNullOrEmpty
        }
        It 'non-zero SetAttribute Status => error (rejected write, happy path unchanged)' {
            $r = Invoke-Dell -CurrentVal 'Disabled' -SetStatus 5
            $r.Error | Should Match 'rejected'
        }
    }

    # --- Unreadable state: the REAL resolvedStatus mapping (extracted from the live
    #     worker) turns the Unknown flag into a distinct 'Unknown' status. ---
    Context 'Unreadable state resolves to a distinct Unknown status' {
        $lw = & $sbm { $script:SbeLiveWorker }
        $assign = $lw.Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                                    $n.Left.Extent.Text -eq '$resolvedStatus' }, $true) | Select-Object -First 1
        $mapper = [scriptblock]::Create("param(`$result) $($assign.Extent.Text); `$resolvedStatus")

        It 'Unknown flag => Unknown (NOT conflated with Skipped/already-compliant)' {
            (& $mapper ([pscustomobject]@{ Unknown = $true;  Skipped = $false; Error = 'cannot read' })) | Should Be 'Unknown'
        }
        It 'already-compliant (Skipped) still => Skipped' {
            (& $mapper ([pscustomobject]@{ Unknown = $false; Skipped = $true;  Error = '' })) | Should Be 'Skipped'
        }
        It 'clean enable => Success; hard error => Error (happy paths unchanged)' {
            (& $mapper ([pscustomobject]@{ Unknown = $false; Skipped = $false; Error = '' }))     | Should Be 'Success'
            (& $mapper ([pscustomobject]@{ Unknown = $false; Skipped = $false; Error = 'boom' })) | Should Be 'Error'
        }
    }

    # --- Unreadable state: the REAL payload emits the distinct Unknown marker (not
    #     Skipped) when Confirm-SecureBootUEFI fails generically. Run isolated so the
    #     payload's self-delete ($PSCommandPath) can never touch the test file. ---
    Context 'Payload flags an unreadable Secure Boot state as Unknown (not Skipped)' {
        It 'Confirm-SecureBootUEFI generic failure => CurrentValue Unknown, Skipped=$false, Unknown=$true' {
            $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('sbe_' + [guid]::NewGuid().ToString('N') + '.json')
            & {
                param($src, $ResultPath)
                $PSCommandPath = $null   # protect the test file from the payload's self-delete
                $BIOSPassword  = 'x'
                function Get-CimInstance { [CmdletBinding()] param($ClassName, $Namespace) [pscustomobject]@{ Manufacturer = 'Dell Inc.' } }
                function Confirm-SecureBootUEFI { [CmdletBinding()] param() throw 'generic EFI provider failure' }
                Invoke-Expression $src
            } $payload $tmp
            $obj = Get-Content -LiteralPath $tmp -Raw | ConvertFrom-Json
            Remove-Item -LiteralPath $tmp -Force -EA SilentlyContinue
            $obj.CurrentValue | Should Be 'Unknown'
            $obj.Skipped      | Should Be $false
            $obj.Unknown      | Should Be $true
        }
    }
}

# -----------------------------------------------------------------------------
Describe 'FIX 5 - ACAS "unchanged after update" is a distinct UNCONFIRMED state (JanetWeb.acas.psm1)' {

    $am = Import-Module (Join-Path $script:Root 'modules\JanetWeb.acas.psm1') -Force -PassThru

    $okOf = & $am { $script:AcasOkOf }

    # Extract the REAL post-verify result-string logic from the update worker and drive it
    # with synthetic pre/post versions, so the module's own classification is exercised.
    $uw  = & $am { $script:AcasUpdateWorker }
    $txt = $uw.ToString()
    $startIdx  = $txt.IndexOf('$marker = "<<PRE=')
    $endToken  = 'return "$updateStr | $diff $marker"'
    $endIdx    = $txt.IndexOf($endToken) + $endToken.Length
    $snippet   = $txt.Substring($startIdx, $endIdx - $startIdx)
    $classify  = [scriptblock]::Create("param(`$preV,`$postV,`$updateStr) $snippet")

    Context 'AcasOkOf success predicate' {
        It 'a plain OK / a confirmed bump counts as OK' {
            (& $okOf 'OK updated') | Should Be $true
            (& $okOf 'OK updated | bumped: 1.2.3 -> 1.2.4 <<PRE=1.2.3>><<POST=1.2.4>>') | Should Be $true
        }
        It 'a hard FAIL counts as NOT-OK' {
            (& $okOf 'FAIL: Session - boom') | Should Be $false
        }
        It 'an UNCONFIRMED result counts as NOT-OK (amber, not green)' {
            (& $okOf 'UNCONFIRMED: version unchanged after update (async update may still be in progress) | OK <<PRE=1.2.3>><<POST=1.2.3>>') | Should Be $false
        }
    }

    Context 'Post-verify classification (real worker source)' {
        It 'version unchanged => UNCONFIRMED and AcasOkOf treats it as NOT-OK' {
            $s = & $classify '1.2.3' '1.2.3' 'OK updated'
            $s            | Should Match '^UNCONFIRMED'
            (& $okOf $s)  | Should Be $false
        }
        It 'version bumped => confirmed, and AcasOkOf treats it as OK (happy path)' {
            $s = & $classify '1.2.3' '1.2.4' 'OK updated'
            $s            | Should Match 'bumped: 1.2.3 -> 1.2.4'
            $s            | Should Not Match '^UNCONFIRMED'
            (& $okOf $s)  | Should Be $true
        }
    }
}
