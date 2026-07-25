# =============================================================================
#  Dhcp.IpValidation.Tests.ps1 - Pester 3.4 for the DHCP tool's IP-validation
#  safety gate (loop16). dhcp is a DESTRUCTIVE tool (it writes scope-option values
#  and casts scope-ids to [ipaddress] on a remote DHCP server) yet had NO dedicated
#  test. Test-JanetIpv4 is the gate that stops a malformed/truncated IP from being
#  stored as an option value or reaching the remote [ipaddress] cast. Its whole point
#  is to reject the classful shorthand that .NET's lenient TryParse SILENTLY widens
#  ('192.168.1' -> 192.168.0.1, '10' -> 0.0.0.10) via a parse round-trip.
#
#  Internal (non-exported) helpers are exercised in the module's session state with
#  `& $mod { ... }` (same idiom as Message.SelfGuard.Tests.ps1) - no production change.
#
#  Run:  Invoke-Pester -Path .\tests\Dhcp.IpValidation.Tests.ps1
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
$mod = Import-Module (Join-Path $script:Root 'modules\JanetWeb.dhcp.psm1') -Force -PassThru
Add-ShimGuard $mod

function Ipv4([string]$t) { & $mod { param($x) Test-JanetIpv4 $x } $t }

Describe 'dhcp Test-JanetIpv4 - canonical dotted-quad only (destructive-write safety gate)' {
    It 'accepts canonical IPv4 addresses' {
        Ipv4 '192.168.1.1'     | Should Be $true
        Ipv4 '10.0.0.255'      | Should Be $true
        Ipv4 '0.0.0.0'         | Should Be $true
        Ipv4 '255.255.255.255' | Should Be $true
    }
    It 'trims surrounding whitespace' {
        Ipv4 '  10.1.2.3  ' | Should Be $true
    }
    It 'REJECTS classful shorthand that .NET TryParse silently widens' {
        # '192.168.1' -> 192.168.0.1 ; '10.1' -> 10.0.0.1 ; '10' -> 0.0.0.10. The
        # round-trip (ToString -eq trimmed input) must reject each so a truncated paste
        # never becomes a WRONG scope-id or option value on the destructive path.
        Ipv4 '192.168.1' | Should Be $false
        Ipv4 '10.1'      | Should Be $false
        Ipv4 '10'        | Should Be $false
    }
    It 'REJECTS non-canonical leading-zero / octal-looking octets' {
        # Regardless of how .NET interprets a leading zero, the round-trip differs -> reject.
        Ipv4 '010.0.0.1' | Should Be $false
        Ipv4 '1.2.3.04'  | Should Be $false
    }
    It 'REJECTS out-of-range octets and garbage' {
        Ipv4 '256.1.1.1' | Should Be $false
        Ipv4 '1.2.3.4.5' | Should Be $false
        Ipv4 'abc'       | Should Be $false
        Ipv4 ''          | Should Be $false
        Ipv4 '   '       | Should Be $false
    }
    It 'REJECTS IPv6 (this is an IPv4-only gate)' {
        Ipv4 '::1'     | Should Be $false
        Ipv4 'fe80::1' | Should Be $false
    }
}

Describe 'dhcp Get-JanetValidIpList - split / validate / canonicalize / dedupe' {
    It 'splits a mixed blob into valid (deduped, in order) and invalid' {
        $r = & $mod { param($b) Get-JanetValidIpList $b } "10.0.0.1, 10.0.0.1`n192.168.1; bogus 10; 172.16.0.5"
        (@($r.Valid)   -join ',') | Should Be '10.0.0.1,172.16.0.5'
        (@($r.Invalid) -join ',') | Should Be '192.168.1,bogus,10'
    }
    It 'returns empty arrays for an all-invalid blob (no crash)' {
        $r = & $mod { param($b) Get-JanetValidIpList $b } 'nope; 999.1.1.1'
        @($r.Valid).Count | Should Be 0
        (@($r.Invalid) -join ',') | Should Be 'nope,999.1.1.1'
    }
}

# loop65 (item74): the remote DHCP bulk script fail-closes on a read failure (Status='ReadError' -
# it declines to write because it could not read the current option value). The LOCAL bulk result
# handler then laundered that refusal: 'ReadError' matched no counter bucket, both audit switch
# defaults booked TouchHost/Success, and the summary read "0 error(s)". Now the counter's final
# branch is a fail-closed catch-all and both switch defaults book Failure, with an explicit
# ReadError case. Behavioral (shim the remote call) + a static assert that no default books Success.
Describe 'dhcp 1.1.9 - a bulk ReadError scope is a Failure, never a laundered Success' {
    It 'manifest version is at least 1.1.9 (floor; newest exact pin = loop66 destructive-guards Describe, v1.1.10)' {
        ([version][string](& $mod { Get-JanetToolManifest }).version -ge [version]'1.1.9') | Should Be $true
    }
    It 'a ReadError scope -> Failure audit, counted in summary.failed, honest row status' {
        $events = New-Object System.Collections.ArrayList
        $send = { param($e) [void]$events.Add($e) }
        $res = & $mod {
            param($snd)
            $__shims = Save-ShimState @('Invoke-JanetOnDhcpCancelable')
            function script:Invoke-JanetOnDhcpCancelable {
                param($Server, $Script, $Arguments, $Credential, $CancelCheck, $UseSsl)
                @{ Cancelled = $false; Result = @(
                    [pscustomobject]@{ ScopeId = '192.168.1.0'; Status = 'ReadError'; Before = @(); After = @(); Error = 'RPC failure reading option 6' }
                ) }
            }
            try {
                Invoke-JanetDhcpBulk -Server 'DHCP01' -ScopeIds @('192.168.1.0') -OptionId 6 -Ips @('10.0.0.1') -Mode 'Append' -Credential $null -Send $snd -CancelCheck { $false } -DryRun $false
            } finally { Restore-ShimState $__shims }   # audit 2026-07-25: the old 'Remove-Item function:script:X' spelling was inert (see Add-ShimGuard) - the shim leaked
        } $send

        [int]$res.summary.failed | Should Be 1
        [int]$res.summary.ok     | Should Be 0
        $audit = @($events | Where-Object { $_.type -eq 'audit' })[0]
        [string]$audit.result    | Should Be 'Failure'
        ([string]$audit.detail -match 'REFUSED') | Should Be $true
        $row = @($events | Where-Object { $_.type -eq 'row' })[0]
        [string]$row.Status      | Should Be 'ReadError'
    }
    It 'neither bulk audit switch default books Success (fail-closed default)' {
        $src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.dhcp.psm1') -Raw
        ($src -match "default\s*\{[^}]*result='Success'[^}]*bulk-") | Should Be $false
    }
}

# loop66 (item75): dhcp was the only destructive engine with NO self-guard and NO typed confirm-word -
# the target filter admitted localhost/127.0.0.1/the dispatcher's own name. The 4 write actions (apply +
# bulk-*) now refuse fail-closed BEFORE any DHCP session unless the operator typed APPLY, and refuse when
# the target resolves to the box running JANET. connect/load are read-only and ungated.
Describe 'dhcp 1.1.10 - destructive actions gated by confirm-word + self-guard' {
    function Invoke-DhcpAction([string]$aid, [hashtable]$p) {
        $evs = New-Object System.Collections.ArrayList
        $emit = { param($e) [void]$evs.Add($e) }
        $res = & $mod { param($a,$pp,$em) Invoke-JanetToolAction -ActionId $a -Params $pp -Credential $null -Emit $em } $aid $p $emit
        @{ Result = $res; Events = @($evs) }
    }

    It 'manifest version is at least 1.1.10 (floor; newest exact pin = loop67 dryRun Describe, v1.1.11)' {
        ([version][string](& $mod { Get-JanetToolManifest }).version -ge [version]'1.1.10') | Should Be $true
    }
    It 'all four destructive actions require a confirm input; connect/load do not' {
        $mani = & $mod { Get-JanetToolManifest }
        foreach ($aid in @('apply','bulk-append','bulk-prepend','bulk-remove')) {
            $a = @($mani.actions | Where-Object { $_.id -eq $aid })[0]
            $c = @($a.inputs | Where-Object { $_.name -eq 'confirm' })[0]
            $c                | Should Not BeNullOrEmpty
            [bool]$c.required | Should Be $true
        }
        foreach ($aid in @('connect','load')) {
            $a = @($mani.actions | Where-Object { $_.id -eq $aid })[0]
            @($a.inputs | Where-Object { $_.name -eq 'confirm' }).Count | Should Be 0
        }
    }
    It 'Test-DhcpHostIsSelf: loopback and this box are self; a remote name is not' {
        (& $mod { Test-DhcpHostIsSelf '127.0.0.1' }) | Should Be $true
        (& $mod { param($h) Test-DhcpHostIsSelf $h } $env:COMPUTERNAME) | Should Be $true
        (& $mod { Test-DhcpHostIsSelf 'DHCP-REMOTE-XYZ' }) | Should Be $false
    }
    It 'apply with no confirm-word -> rejected before any DHCP session' {
        $o = Invoke-DhcpAction 'apply' @{ targets = 'DHCP-REMOTE-1'; scopeId = '192.168.1.0'; newValues = '10.0.0.1' }
        [bool]$o.Result.summary.rejected | Should Be $true
        @($o.Events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'err' -and $_.text -match 'type APPLY' }).Count | Should BeGreaterThan 0
    }
    It 'apply with a wrong confirm-word -> rejected' {
        $o = Invoke-DhcpAction 'bulk-append' @{ targets = 'DHCP-REMOTE-1'; scopeIds = '192.168.1.0'; ipAddresses = '10.0.0.1'; confirm = 'YES' }
        [bool]$o.Result.summary.rejected | Should Be $true
    }
    It 'apply with APPLY but a SELF target -> self-guard rejected (selfSkipped=1)' {
        $o = Invoke-DhcpAction 'apply' @{ targets = '127.0.0.1'; scopeId = '192.168.1.0'; newValues = '10.0.0.1'; confirm = 'APPLY' }
        [bool]$o.Result.summary.rejected   | Should Be $true
        [int]$o.Result.summary.selfSkipped | Should Be 1
        @($o.Events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'err' -and $_.text -match 'Self-guard' }).Count | Should BeGreaterThan 0
    }
}

# loop67 (item76): the dry-run selector on the DESTRUCTIVE write actions used the shared $asBool, which
# resolves any unrecognized token to $false = a LIVE write, so a typo ('TRUE ', 'checked', 'dry') silently
# wrote to a live DHCP server (secureboot loop-58 class). Get-DhcpDryRunSafe fails CLOSED: a live write
# needs an absent value or an explicit recognized false; any present-but-unrecognized token stays DRY.
Describe 'dhcp 1.1.11 - dryRun parse fails closed (unrecognized token stays DRY)' {
    function DryOf { param($v) & $mod { param($x) Get-DhcpDryRunSafe $x } $v }

    It 'manifest version is at least 1.1.11 (floor; newest exact pin = loop68 null-result Describe, v1.1.12)' {
        ([version][string](& $mod { Get-JanetToolManifest }).version -ge [version]'1.1.11') | Should Be $true
    }
    It 'absent/empty -> live (the documented write default)' {
        (DryOf $null) | Should Be $false
        (DryOf '')    | Should Be $false
    }
    It 'explicit recognized false tokens -> live' {
        foreach ($t in 'false','0','no','off','False','OFF') { (DryOf $t) | Should Be $false }
        (DryOf $false) | Should Be $false
    }
    It 'explicit recognized true tokens -> dry' {
        foreach ($t in 'true','1','yes','on','TRUE') { (DryOf $t) | Should Be $true }
        (DryOf $true) | Should Be $true
    }
    It 'a present-but-UNRECOGNIZED token stays DRY (the fix; $asBool would have gone live)' {
        foreach ($t in 'dry','checked','maybe','TRUE ','2','y') { (DryOf $t) | Should Be $true }
    }
}

# loop68 (item78): Invoke-JanetDhcpApply read $applyCall.Result | Select -First 1; a NULL/empty result
# (the remote apply confirmed neither a Set nor a Remove - an error that didn't throw, a lost pipeline)
# made [bool]$null.Removed=$false -> Status='Changed' -> a clean VulnPatched/Success for a change that
# could not be confirmed. Now a null result is a Failure. Behavioral: shim the two remote seams (pre-read
# returns valid current state so the write is reached; the write returns an EMPTY result).
Describe 'dhcp 1.1.12 - an apply that returns NO result is a Failure, not a false Changed/Success' {
    It 'manifest version is at least 1.1.12 (floor; newest exact pin = loop69 optionId Describe, v1.1.13)' {
        ([version][string](& $mod { Get-JanetToolManifest }).version -ge [version]'1.1.12') | Should Be $true
    }
    It 'apply write returns an empty result -> Status Error, failed=1, audit Failure (not Changed/Success)' {
        $events = New-Object System.Collections.ArrayList
        $send = { param($e) [void]$events.Add($e) }
        $res = & $mod {
            param($snd)
            $__shims = Save-ShimState @('Test-JanetWsmanReachable','Invoke-JanetOnDhcp','Invoke-JanetOnDhcpCancelable')
            function script:Test-JanetWsmanReachable { param($Server, $TimeoutMs = 3000) @{ Reachable = $true; UseSsl = $false } }
            function script:Invoke-JanetOnDhcp {
                [CmdletBinding()] param($Server, $Script, $Arguments, $Credential, $UseSsl)
                [pscustomobject]@{ Ok = $true; Values = @('10.0.0.9'); NotSet = $false; Err = $null }   # valid pre-read
            }
            function script:Invoke-JanetOnDhcpCancelable {
                [CmdletBinding()] param($Server, $Script, $Arguments, $Credential, $CancelCheck, $UseSsl)
                [pscustomobject]@{ Cancelled = $false; Result = @() }   # the WRITE returns NOTHING
            }
            try {
                Invoke-JanetDhcpApply -Server 'TESTSRV' -ScopeId '10.0.0.0' -OptionId 6 -NewValues @('10.0.0.1','10.0.0.2') -Credential $null -Send $snd
            } finally { Restore-ShimState $__shims }   # audit 2026-07-25: the old 'Remove-Item function:script:X' spelling was inert (see Add-ShimGuard) - the shim leaked
        } $send

        [string]$res.summary.status | Should Be 'Error'
        [int]$res.summary.failed    | Should Be 1
        [int]$res.summary.ok        | Should Be 0
        $audit = @($events | Where-Object { $_.type -eq 'audit' })[0]
        [string]$audit.result       | Should Be 'Failure'
        ([string]$audit.detail -match 'NOT confirmed') | Should Be $true
    }
}

# loop69 (item77): a non-numeric optionId on a DESTRUCTIVE write silently fell back to option 6 (DNS
# Servers) - so an operator who meant option 60/66 and typo'd would live-replace the scope's DNS servers,
# a wrong-target write. Now a destructive action aborts on an unparseable optionId; a read-only load may
# still warn-and-default (it changes nothing).
Describe 'dhcp 1.1.13 - a non-numeric optionId aborts a destructive write (no silent retarget to option 6/DNS)' {
    function Invoke-DhcpAction2([string]$aid, [hashtable]$p) {
        $evs = New-Object System.Collections.ArrayList
        $emit = { param($e) [void]$evs.Add($e) }
        $res = & $mod { param($a,$pp,$em) Invoke-JanetToolAction -ActionId $a -Params $pp -Credential $null -Emit $em } $aid $p $emit
        @{ Result = $res; Events = @($evs) }
    }

    It 'manifest version is at least 1.1.13 (floor; newest exact pin = loop75 hint Describe, v1.1.14)' {
        ([version][string](& $mod { Get-JanetToolManifest }).version -ge [version]'1.1.13') | Should Be $true
    }
    It 'apply with a non-numeric optionId -> rejected, does NOT default to option 6' {
        $o = Invoke-DhcpAction2 'apply' @{ targets = 'DHCP-REMOTE-1'; scopeId = '10.0.0.0'; newValues = '10.0.0.1'; confirm = 'APPLY'; optionId = '6o' }
        [bool]$o.Result.summary.rejected | Should Be $true
        @($o.Events | Where-Object { $_.type -eq 'log' -and $_.level -eq 'err' -and $_.text -match 'not numeric' -and $_.text -match 'DNS' }).Count | Should BeGreaterThan 0
    }
    It 'a bulk write with a non-numeric optionId -> rejected too' {
        $o = Invoke-DhcpAction2 'bulk-append' @{ targets = 'DHCP-REMOTE-1'; scopeIds = '10.0.0.0'; ipAddresses = '10.0.0.1'; confirm = 'APPLY'; optionId = 'xyz' }
        [bool]$o.Result.summary.rejected | Should Be $true
    }
}

# loop75 (informative-failures theme): dhcp's 5 failure-path catches used the thin, auth-only
# Get-JanetWsmanAuthHint. They now use the shared Get-JanetTroubleshootHint (a strict superset -
# DNS/RPC/SMB/timeout/etc.), and the dead local function is retired. Static analysis.
Describe 'dhcp 1.1.14 - failure hints upgraded from thin auth-only to the shared troubleshoot engine' {
    $src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.dhcp.psm1') -Raw

    It 'manifest version is at least 1.1.14 (floor; newest exact pin = audit 2026-07-25 Describe, v1.1.16)' {
        ([version][string](& $mod { Get-JanetToolManifest }).version -ge [version]'1.1.14') | Should Be $true
    }
    It 'dhcp imports the shared troubleshoot engine' {
        ($src -match 'Import-Module.*JanetWeb\.troubleshoot\.psm1') | Should Be $true
    }
    It 'the failure catches use the shared Get-JanetTroubleshootHint (>=5 call sites)' {
        ([regex]::Matches($src, '\$hint\s*=\s*Get-JanetTroubleshootHint\b').Count -ge 5) | Should Be $true
    }
    It 'the dead thin Get-JanetWsmanAuthHint FUNCTION and its calls are gone' {
        ($src -match 'function Get-JanetWsmanAuthHint')       | Should Be $false
        ($src -match '=\s*Get-JanetWsmanAuthHint\s*-Message') | Should Be $false
    }
}

# audit 2026-07-24 - three defects that between them made the destructive half of dhcp
# unusable and its one multi-scope success path unreadable:
#   [P1] the view never sent the `confirm` param the server-side typed-APPLY gate demands
#        (and used ctx.confirm, which silently ignores confirmWord), so EVERY apply/bulk-*
#        was refused server-side - the write half of the tool had presumably never worked;
#   [P1] the remote bulk script's `,$out.ToArray()` self-guard survives the [powershell]
#        handle, so @($bulkCall.Result) unrolled only the outer collection and a successful
#        N-scope write booked 0 changed + 1 "unexpected status" failure on one junk row;
#   [P4] expectedOld - the entire optimistic-concurrency guard - was undeclared in the
#        manifest, so the action contract hid its only anti-clobber input.
Describe 'dhcp 1.1.15 - confirm-param wiring, multi-scope bulk unwrapping, declared expectedOld' {
    $viewPath = Join-Path $script:Root 'web\js\views\dhcp.view.js'
    $view     = Get-Content $viewPath -Raw

    It 'manifest version is at least 1.1.15 (floor; the exact pin moved to the 1.1.16 Describe)' {
        ([version][string](& $mod { Get-JanetToolManifest }).version -ge [version]'1.1.15') | Should Be $true
    }

    # --- [P1] the view <-> gate wiring contract (static: this is a wiring contract, and
    # the params object is built inline at the ctx.run call site). ---
    It 'the view SENDS confirm=APPLY on both destructive run calls (the gate requires the typed word)' {
        ($view -match "ctx\.run\('apply',[^\r\n]*confirm:\s*'APPLY'")           | Should Be $true
        ($view -match "ctx\.run\('bulk-' \+ mode,[^\r\n]*confirm:\s*'APPLY'")   | Should Be $true
    }
    It 'the word the view sends is the word the engine gate demands, CASE-EXACTLY' {
        # audit 2026-07-24 (fable re-audit F3): the gate was `-ne`, which is case-INSENSITIVE,
        # so 'apply' passed a gate whose own error text says "exactly". Standardised to -cne
        # across all eight server-side confirm gates.
        $src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.dhcp.psm1') -Raw
        ($src -match "\`$Params\['confirm'\]\s*-cne\s*'APPLY'") | Should Be $true
    }
    It 'both destructive dialogs use ctx.arm with confirmWord APPLY (ctx.confirm IGNORES confirmWord)' {
        # >=2 arming dialogs (apply + bulk) and a typed word on each LIVE path.
        ([regex]::Matches($view, 'ctx\.arm\(').Count -ge 2)                              | Should Be $true
        ([regex]::Matches($view, "confirmWord:\s*dry \? null : 'APPLY'").Count -ge 2)     | Should Be $true
    }
    It 'no destructive dialog is left on ctx.confirm (the silent-drop failure mode)' {
        # ctx.confirm survives ONLY for the informational OK-boxes (invalid IP, no scopes
        # checked, ...); neither APPLY nor BULK confirmation may sit on it.
        ($view -match "ctx\.confirm\(\{[^\r\n]*title:\s*'Confirm APPLY")      | Should Be $false
        ($view -match "ctx\.confirm\(\{[^\r\n]*title:\s*'Confirm BULK")       | Should Be $false
    }

    # --- [P2] Remove option must post an EMPTY new-values list (the engine refuses
    # removeOption together with supplied values, so the dialog's promise was unreachable). ---
    It "the view posts an empty newValues when 'Remove option' is checked" {
        ($view -match "newValues:\s*removeOpt \? '' :") | Should Be $true
    }
    It 'the engine still refuses the values+removeOption combination (the guard we are now honouring)' {
        $evs = New-Object System.Collections.ArrayList
        $emit = { param($e) [void]$evs.Add($e) }
        $res = & $mod { param($pp,$em) Invoke-JanetToolAction -ActionId 'apply' -Params $pp -Credential $null -Emit $em } `
                 @{ targets='DHCP-REMOTE-1'; scopeId='10.0.0.0'; newValues='10.0.0.1'; removeOption='true'; confirm='APPLY' } $emit
        [int]$res.summary.total | Should Be 0
        @($evs | Where-Object { $_.type -eq 'log' -and $_.level -eq 'err' -and $_.text -match 'Clear one or the other' }).Count | Should BeGreaterThan 0
    }

    # --- [P4] the view must not silently retarget a different DHCP server. ---
    It 'load / apply / bulk target the CONNECTED server, not the live field value' {
        ($view -match 'function activeServer\(')                       | Should Be $true
        ($view -match "ctx\.run\('load',\s*\{\s*targets:\s*srv")       | Should Be $true
        ($view -match "ctx\.run\('apply',\s*\{\s*targets:\s*srv")      | Should Be $true
        ($view -match "ctx\.run\('bulk-' \+ mode,\s*\{\s*targets:\s*srv") | Should Be $true
        ($view -match "targets:\s*serverInput\.value")                 | Should Be $false
    }

    # --- [P1] one row PER SCOPE out of a multi-scope bulk run. ---
    function Invoke-BulkWithResult($resultValue, $scopeIds) {
        $events = New-Object System.Collections.ArrayList
        $send = { param($e) [void]$events.Add($e) }
        $res = & $mod {
            param($snd, $rv, $sids)
            $__shims = Save-ShimState @('Test-JanetWsmanReachable','Invoke-JanetOnDhcpCancelable')
            function script:Test-JanetWsmanReachable { param($Server, $TimeoutMs = 3000) @{ Reachable = $true; UseSsl = $false } }
            function script:Invoke-JanetOnDhcpCancelable {
                [CmdletBinding()] param($Server, $Script, $Arguments, $Credential, $CancelCheck, $UseSsl)
                @{ Cancelled = $false; Result = $rv }
            }
            try {
                Invoke-JanetDhcpBulk -Server 'DHCP01' -ScopeIds $sids -OptionId 6 -Ips @('10.0.0.1') -Mode 'Append' -Credential $null -Send $snd -CancelCheck { $false } -DryRun $false
            } finally { Restore-ShimState $__shims }   # audit 2026-07-25: the old 'Remove-Item function:script:X' spelling was inert (see Add-ShimGuard) - the shim leaked
        } $send $resultValue $scopeIds
        @{ Result = $res; Events = @($events) }
    }
    $threeRecs = @(
        [pscustomobject]@{ ScopeId='10.0.1.0'; Status='Changed';  Before=@('10.0.0.9'); After=@('10.0.0.9','10.0.0.1'); Error=$null }
        [pscustomobject]@{ ScopeId='10.0.2.0'; Status='Changed';  Before=@();           After=@('10.0.0.1');            Error=$null }
        [pscustomobject]@{ ScopeId='10.0.3.0'; Status='NoChange'; Before=@('10.0.0.1'); After=@('10.0.0.1');            Error=$null }
    )
    $threeScopes = @('10.0.1.0','10.0.2.0','10.0.3.0')

    It 'a NESTED result (the real seam shape) yields one row per scope, not one junk row' {
        # (,$recs) reproduces exactly what the live call returns: ONE output object that
        # IS the record array, because the remote ,$out.ToArray() survived the handle.
        # Old behaviour: 1 row, Status = a space-joined member-enumeration blob, 0 changed,
        # 1 "unexpected status" failure.
        $o = Invoke-BulkWithResult (,$threeRecs) $threeScopes
        @($o.Result.rows).Count       | Should Be 3
        [int]$o.Result.summary.ok     | Should Be 2
        [int]$o.Result.summary.noChange | Should Be 1
        [int]$o.Result.summary.failed | Should Be 0
        (@($o.Result.rows | ForEach-Object { [string]$_.ScopeId }) -join ',') | Should Be '10.0.1.0,10.0.2.0,10.0.3.0'
        (@($o.Result.rows | ForEach-Object { [string]$_.Status })  -join ',') | Should Be 'Changed,Changed,NoChange'
        @($o.Events | Where-Object { $_.type -eq 'row' }).Count | Should Be 3
        @($o.Events | Where-Object { $_.type -eq 'audit' -and $_.detail -match 'unexpected status' }).Count | Should Be 0
    }
    It 'an ALREADY-FLAT result set is unchanged by the deeper unwrap (shape-tolerant)' {
        $o = Invoke-BulkWithResult $threeRecs $threeScopes
        @($o.Result.rows).Count   | Should Be 3
        [int]$o.Result.summary.ok | Should Be 2
    }

    # --- [P4] expectedOld declared in the action contract. ---
    It "apply declares expectedOld (optional: ABSENT means no staleness check)" {
        $a  = @((& $mod { Get-JanetToolManifest }).actions | Where-Object { $_.id -eq 'apply' })[0]
        $eo = @($a.inputs | Where-Object { $_.name -eq 'expectedOld' })[0]
        $eo                 | Should Not BeNullOrEmpty
        [bool]$eo.required  | Should Be $false
        ([string]$eo.label -match '(?i)concurrency') | Should Be $true
    }
    It 'the declared expectedOld is the one the dispatcher actually reads' {
        $src = Get-Content (Join-Path $script:Root 'modules\JanetWeb.dhcp.psm1') -Raw
        ($src -match "\`$Params\.ContainsKey\('expectedOld'\)") | Should Be $true
    }

    # --- [P3] dry run must preview what the live path would book. ---
    It 'a dry-run remove of an ALREADY-UNSET option previews NoChange, not a phantom WouldRemove' {
        $events = New-Object System.Collections.ArrayList
        $send = { param($e) [void]$events.Add($e) }
        $res = & $mod {
            param($snd)
            $__shims = Save-ShimState @('Test-JanetWsmanReachable','Invoke-JanetOnDhcp')
            function script:Test-JanetWsmanReachable { param($Server, $TimeoutMs = 3000) @{ Reachable = $true; UseSsl = $false } }
            function script:Invoke-JanetOnDhcp {
                [CmdletBinding()] param($Server, $Script, $Arguments, $Credential, $UseSsl)
                [pscustomobject]@{ Ok = $true; Values = @(); NotSet = $true; Err = $null }   # option is NOT set
            }
            try {
                Invoke-JanetDhcpApply -Server 'TESTSRV' -ScopeId '10.0.0.0' -OptionId 6 -NewValues @() -Credential $null -Send $snd -DryRun $true
            } finally { Restore-ShimState $__shims }   # audit 2026-07-25: the old 'Remove-Item function:script:X' spelling was inert (see Add-ShimGuard) - the shim leaked
        } $send
        [string]$res.summary.status | Should Be 'NoChange'
        [string](@($events | Where-Object { $_.type -eq 'row' })[0].Status) | Should Be 'NoChange'
    }
}

# audit 2026-07-25 (fable re-audit follow-up) - two residuals:
#   [P4] editing the CUSTOM option ID after a Load did not invalidate the loaded state, so an
#        APPLY could pair the newly-typed ID with the PREVIOUS option's expectedOld (only
#        caught by the divergence guard when the two options hold different values - two unset
#        options do not diverge);
#   [P4] dry runs auto-send confirm='APPLY' with no typed word. Decision: KEEP the server-side
#        gate unconditional (an exemption would make the one unbypassable refusal depend on the
#        request-controlled dryRun flag) and document the trade-off at the gate + both call
#        sites. These pin the decision so a later pass does not silently flip it.
Describe 'dhcp 1.1.16 - option-ID edits invalidate the loaded state; the APPLY gate stays unconditional' {
    $viewPath = Join-Path $script:Root 'web\js\views\dhcp.view.js'
    $view     = Get-Content $viewPath -Raw
    $src      = Get-Content (Join-Path $script:Root 'modules\JanetWeb.dhcp.psm1') -Raw

    It 'manifest version is exactly 1.1.16 (newest bump holds the exact pin)' {
        [string](& $mod { Get-JanetToolManifest }).version | Should Be '1.1.16'
    }

    # --- [P4] the option-ID box now behaves like the dropdown. ---
    It 'the view tracks WHICH option ID the loaded before-state belongs to' {
        ($view -match 'var loadedOptionId = null;')                | Should Be $true
        ($view -match 'function optionLoaded\(\)')                 | Should Be $true
        ($view -match 'loadedOptionId = opt;')                     | Should Be $true
    }
    It 'typing in the custom-ID box invalidates the loaded state (it was updateBulk alone)' {
        ($view -match "optIdInput\.addEventListener\('input'[^\r\n]*invalidateLoadedOption\(\)") | Should Be $true
        ($view -match "optIdInput\.addEventListener\('input', function \(\) \{ updateBulk\(\); \}\)") | Should Be $false
    }
    It 'committing the typed ID reloads, exactly like the dropdown change does' {
        ($view -match "optIdInput\.addEventListener\('change'[^\r\n]*doLoad\(true\)") | Should Be $true
        ($view -match "optSelect\.addEventListener\('change'[^\r\n]*doLoad\(true\)")  | Should Be $true
    }
    It 'APPLY is gated on a load that matches the current ID (button + hard guard in doApply)' {
        ($view -match 'applyBtn\.disabled = writeActive \|\| !optionLoaded\(\)') | Should Be $true
        ($view -match 'if \(!optionLoaded\(\)\) \{ ctx\.confirm')                | Should Be $true
    }
    It 'an in-flight or failed load leaves nothing armed' {
        ($view -match 'loadedOptionId = null;\r?\n\s*readRun = ctx\.run\(.load.') | Should Be $true
    }

    # --- [P4] the dry-run/confirm trade-off is a recorded decision, not an oversight. ---
    It 'the engine gate is still unconditional (no dryRun exemption)' {
        ($src -match "\`$Params\['confirm'\]\s*-cne\s*'APPLY'")             | Should Be $true
        ($src -match "dryRun[^\r\n]*-and[^\r\n]*confirm")                   | Should Be $false
        ($src -match '(?s)\$isDestructive = \$ActionId -in[^\r\n]*\r?\n\s*if \(\$isDestructive\) \{\s*\r?\n\s*if \(\[string\]\$Params\[.confirm.\]') | Should Be $true
    }
    It 'the trade-off is documented at the gate and at BOTH view call sites' {
        ($src -match '(?i)deliberately NOT exempted for')                        | Should Be $true
        ([regex]::Matches($view, '(?i)trade-off').Count -ge 2)                   | Should Be $true
    }
    It 'the live path still types the word (dry runs still pass through a real arm dialog)' {
        ([regex]::Matches($view, "confirmWord:\s*dry \? null : 'APPLY'").Count -ge 2) | Should Be $true
        ([regex]::Matches($view, 'ctx\.arm\(').Count -ge 2)                           | Should Be $true
    }
}
